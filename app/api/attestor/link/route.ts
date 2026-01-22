import { NextResponse } from "next/server";
import nacl from "tweetnacl";
import { Connection, Keypair, PublicKey, Transaction } from "@solana/web3.js";

export const runtime = "nodejs";

function parseSecretKey(env: string): Uint8Array {
  // supports:
  // 1) JSON array string: "[1,2,3,...]"
  // 2) base64 string
  const s = env.trim();
  if (s.startsWith("[")) return Uint8Array.from(JSON.parse(s));
  return Uint8Array.from(Buffer.from(s, "base64"));
}

function jsonOk(data: any, status = 200) {
  return NextResponse.json(data, { status });
}

export async function POST(req: Request) {
  try {
    // ✅ Dynamic import to bypass Turbopack static export checks
    const anchor = await import("@coral-xyz/anchor");

    const RPC = process.env.SOLANA_RPC_URL || "https://api.devnet.solana.com";
    const PROGRAM_ID = process.env.VERIFICATION_PROGRAM_ID || "Ev4pb62pHYcFHLmV89JRcgQtS39ndBia51X9ne9NmBkH";
    const ATTESTOR_SK = process.env.ATTESTOR_SECRET_KEY;

    if (!ATTESTOR_SK) return jsonOk({ error: "ATTESTOR_SECRET_KEY missing" }, 500);

    const { payload, signatureBase64 } = await req.json();

    // ---- (Optional) verify user signature here if you’re doing consent-gating ----
    // If you already verify elsewhere, you can remove this block.
    if (payload?.wallet && signatureBase64) {
      const msg =
        `Grape Verification Link Request\n` +
        `daoId=${payload.daoId}\n` +
        `platform=${payload.platform}\n` +
        `idHash=${payload.idHashHex}\n` +
        `wallet=${payload.wallet}\n` +
        `walletHash=${payload.walletHashHex}\n` +
        `ts=${payload.ts}\n`;

      const sig = Buffer.from(signatureBase64, "base64");
      const pub = new PublicKey(payload.wallet).toBytes();
      const ok = nacl.sign.detached.verify(Buffer.from(msg), sig, pub);
      if (!ok) return jsonOk({ error: "Invalid wallet signature" }, 400);
    }

    const connection = new Connection(RPC, "confirmed");
    const programId = new PublicKey(PROGRAM_ID);

    // ✅ Attestor keypair (server signer)
    const kp = Keypair.fromSecretKey(parseSecretKey(ATTESTOR_SK));

    // ✅ Minimal “wallet” shim for AnchorProvider (no anchor.Wallet import)
    const wallet = {
      publicKey: kp.publicKey,
      signTransaction: async (tx: Transaction) => {
        tx.partialSign(kp);
        return tx;
      },
      signAllTransactions: async (txs: Transaction[]) => {
        txs.forEach((t) => t.partialSign(kp));
        return txs;
      },
    };

    const provider = new anchor.AnchorProvider(connection, wallet as any, {
      commitment: "confirmed",
    });

    // ✅ Fetch IDL from chain to avoid typing issues
    const program = await anchor.Program.at(programId, provider);

    // ---- Build your PDAs/hashes exactly as your client does ----
    const daoId = new PublicKey(payload.daoId);
    const platformSeed = Number(payload.platformSeed); // 0/1/2/3
    const idHash = Uint8Array.from(Buffer.from(payload.idHashHex, "hex"));
    const walletHash = Uint8Array.from(Buffer.from(payload.walletHashHex, "hex"));

    const [spacePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("space"), daoId.toBuffer()],
      programId
    );

    const [identityPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("identity"),
        spacePda.toBuffer(),
        Buffer.from([platformSeed]),
        Buffer.from(idHash),
      ],
      programId
    );

    const [linkPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("link"), identityPda.toBuffer(), Buffer.from(walletHash)],
      programId
    );

    // ---- Submit TXs ----
    // A) attest identity (attestor-only)
    await (program as any).methods
      .attestIdentity(
        daoId,
        platformSeed,           // platform enum OR your client passes platform too; adjust if needed
        platformSeed,
        Array.from(idHash),
        0                        // expires_at = 0
      )
      .accounts({
        spaceAcct: spacePda,
        attestor: kp.publicKey,
        identity: identityPda,
        payer: kp.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([kp])
      .rpc();

    // B) link wallet (attestor-only, wallet is CHECK account)
    await (program as any).methods
      .linkWallet(daoId, Array.from(walletHash))
      .accounts({
        spaceAcct: spacePda,
        attestor: kp.publicKey,
        identity: identityPda,
        wallet: new PublicKey(payload.wallet),
        link: linkPda,
        payer: kp.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([kp])
      .rpc();

    return jsonOk({
      ok: true,
      space: spacePda.toBase58(),
      identity: identityPda.toBase58(),
      link: linkPda.toBase58(),
      attestor: kp.publicKey.toBase58(),
    });
  } catch (e: any) {
    return jsonOk({ error: String(e?.message || e) }, 500);
  }
}