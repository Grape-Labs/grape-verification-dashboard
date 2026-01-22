import { NextResponse } from "next/server";
import nacl from "tweetnacl";
import { Connection, Keypair, PublicKey, Transaction, SystemProgram } from "@solana/web3.js";

export const runtime = "nodejs";

function parseSecretKey(env: string): Uint8Array {
  const s = env.trim();
  if (s.startsWith("[")) return Uint8Array.from(JSON.parse(s));
  return Uint8Array.from(Buffer.from(s, "base64"));
}

function platformEnumObject(platform: string) {
  // Anchor enum encoding for Rust enums in methods args
  switch ((platform || "").toLowerCase()) {
    case "discord": return { discord: {} };
    case "telegram": return { telegram: {} };
    case "twitter": return { twitter: {} };
    case "email": return { email: {} };
    default: return { discord: {} };
  }
}

function must<T>(v: T | null | undefined, msg: string): T {
  if (v === null || v === undefined || (typeof v === "string" && !v.trim())) {
    throw new Error(msg);
  }
  return v as T;
}

export async function POST(req: Request) {
  try {
    const anchor = await import("@coral-xyz/anchor");

    const RPC = process.env.SOLANA_RPC_URL || "https://api.devnet.solana.com";
    const PROGRAM_ID = process.env.VERIFICATION_PROGRAM_ID || "Ev4pb62pHYcFHLmV89JRcgQtS39ndBia51X9ne9NmBkH";
    // AFTER
    const ATTESTOR_SK = process.env.ATTESTOR_SECRET_KEY;
    must(ATTESTOR_SK, "ATTESTOR_SECRET_KEY missing");

    // ✅ re-bind after check so TS knows it’s a string
    const attestorSk = ATTESTOR_SK as string;
    const kp = Keypair.fromSecretKey(parseSecretKey(attestorSk));

    const { payload, signatureBase64 } = await req.json();

    must(payload, "Missing payload");
    must(payload.daoId, "payload.daoId missing");
    must(payload.platform, "payload.platform missing");
    must(payload.platformSeed, "payload.platformSeed missing");
    must(payload.idHashHex, "payload.idHashHex missing");
    must(payload.wallet, "payload.wallet missing");
    must(payload.walletHashHex, "payload.walletHashHex missing");
    must(payload.ts, "payload.ts missing");
    must(signatureBase64, "signatureBase64 missing");

    // Verify wallet signature (your exact message format)
    const msg =
      `Grape Verification Link Request\n` +
      `daoId=${payload.daoId}\n` +
      `platform=${payload.platform}\n` +
      `idHash=${payload.idHashHex}\n` +
      `wallet=${payload.wallet}\n` +
      `walletHash=${payload.walletHashHex}\n` +
      `ts=${payload.ts}\n`;

    const sig = Buffer.from(signatureBase64, "base64");
    const walletPk = new PublicKey(payload.wallet);

    const ok = nacl.sign.detached.verify(
      Buffer.from(msg),
      sig,
      walletPk.toBytes()
    );
    if (!ok) {
      return NextResponse.json({ error: "Invalid wallet signature" }, { status: 400 });
    }

    const connection = new Connection(RPC, "confirmed");
    const programId = new PublicKey(PROGRAM_ID);

    // Minimal wallet shim for AnchorProvider
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

    // Fetch IDL from chain
    const program = await anchor.Program.at(programId, provider);

    // Parse inputs
    const daoId = new PublicKey(payload.daoId);
    const platformSeed = Number(payload.platformSeed);
    const idHash = Uint8Array.from(Buffer.from(payload.idHashHex, "hex"));
    const walletHash = Uint8Array.from(Buffer.from(payload.walletHashHex, "hex"));

    if (idHash.length !== 32) throw new Error("idHashHex must be 32 bytes");
    if (walletHash.length !== 32) throw new Error("walletHashHex must be 32 bytes");

    // PDAs
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

    // IMPORTANT: i64 args should be BN
    const expiresAt = new anchor.BN(0);

    // 1) Attest identity
    await (program as any).methods
      .attestIdentity(
        daoId,
        platformEnumObject(payload.platform), // enum
        platformSeed,                         // u8
        Array.from(idHash),                   // [u8;32]
        expiresAt                             // i64
      )
      .accounts({
        spaceAcct: spacePda,
        attestor: kp.publicKey,
        identity: identityPda,
        payer: kp.publicKey,
        systemProgram: SystemProgram.programId, // ✅ from web3.js (NOT anchor.web3)
      })
      .signers([kp])
      .rpc();

    // 2) Link wallet
    await (program as any).methods
      .linkWallet(daoId, Array.from(walletHash))
      .accounts({
        spaceAcct: spacePda,
        attestor: kp.publicKey,
        identity: identityPda,
        wallet: walletPk,
        link: linkPda,
        payer: kp.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([kp])
      .rpc();

    return NextResponse.json({
      ok: true,
      space: spacePda.toBase58(),
      identity: identityPda.toBase58(),
      link: linkPda.toBase58(),
      attestor: kp.publicKey.toBase58(),
    });
  } catch (e: any) {
    return NextResponse.json({ error: String(e?.message || e) }, { status: 500 });
  }
}