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
  switch ((platform || "").toLowerCase()) {
    case "discord": return { discord: {} };
    case "telegram": return { telegram: {} };
    case "twitter": return { twitter: {} };
    case "email": return { email: {} };
    default: return { discord: {} };
  }
}

function mustString(v: any, msg: string): string {
  if (typeof v !== "string" || !v.trim()) throw new Error(msg);
  return v.trim();
}

function mustNumber(v: any, msg: string): number {
  const n = Number(v);
  if (!Number.isFinite(n)) throw new Error(msg);
  return n;
}

function mustPubkey(v: any, msg: string): PublicKey {
  const s = mustString(v, msg);
  try {
    return new PublicKey(s);
  } catch {
    throw new Error(`${msg} (bad pubkey: ${s})`);
  }
}

function mustU8(v: any, msg: string): number {
  const n = mustNumber(v, msg);
  if (n < 0 || n > 255 || Math.floor(n) !== n) throw new Error(`${msg} (must be u8 0-255)`);
  return n;
}

function mustHex32(v: any, msg: string): Uint8Array {
  const s = mustString(v, msg);
  if (!/^[0-9a-fA-F]{64}$/.test(s)) throw new Error(`${msg} (must be 64 hex chars)`);
  const bytes = Uint8Array.from(Buffer.from(s, "hex"));
  if (bytes.length !== 32) throw new Error(`${msg} (must be 32 bytes hex)`);
  return bytes;
}

export async function POST(req: Request) {
  try {
    const anchorMod = await import("@coral-xyz/anchor");
    const { AnchorProvider, Program, BN } = anchorMod as any;

    const RPC = process.env.SOLANA_RPC_URL || "https://api.devnet.solana.com";
    const PROGRAM_ID = process.env.VERIFICATION_PROGRAM_ID || "Ev4pb62pHYcFHLmV89JRcgQtS39ndBia51X9ne9NmBkH";

    const ATTESTOR_SK = mustString(process.env.ATTESTOR_SECRET_KEY, "ATTESTOR_SECRET_KEY missing");
    const kp = Keypair.fromSecretKey(parseSecretKey(ATTESTOR_SK));

    const body = await req.json().catch(() => null);
    if (!body) throw new Error("Invalid JSON body");

    const payload = body.payload;
    if (!payload) throw new Error("payload missing");
    const signatureBase64 = mustString(body.signatureBase64, "signatureBase64 missing");

    // ✅ strict payload guards (these prevent `_bn` undefined errors)
    const daoIdStr = mustString(payload?.daoId, "payload.daoId missing/invalid");
    const platform = mustString(payload?.platform, "payload.platform missing/invalid");
    const platformSeed = mustU8(payload?.platformSeed, "payload.platformSeed missing/invalid");

    const idHash = mustHex32(payload?.idHashHex, "payload.idHashHex missing/invalid");
    const walletHash = mustHex32(payload?.walletHashHex, "payload.walletHashHex missing/invalid");

    const walletStr = mustString(payload?.wallet, "payload.wallet missing/invalid");
    const ts = mustString(String(payload?.ts ?? ""), "payload.ts missing/invalid");

    // ✅ Build exactly the message your client signs (must match byte-for-byte)
    const msg =
      `Grape Verification Link Request\n` +
      `daoId=${daoIdStr}\n` +
      `platform=${platform}\n` +
      `idHash=${Buffer.from(idHash).toString("hex")}\n` +
      `wallet=${walletStr}\n` +
      `walletHash=${Buffer.from(walletHash).toString("hex")}\n` +
      `ts=${ts}\n`;

    const sig = Buffer.from(signatureBase64, "base64");
    const walletPk = mustPubkey(walletStr, "payload.wallet missing/invalid");

    const ok = nacl.sign.detached.verify(Buffer.from(msg), sig, walletPk.toBytes());
    if (!ok) {
      return NextResponse.json(
        {
          error: "Invalid wallet signature",
          debug: {
            wallet: walletPk.toBase58(),
            msg,
            sigLen: sig.length,
          },
        },
        { status: 400 }
      );
    }

    const connection = new Connection(RPC, "confirmed");
    const programId = mustPubkey(PROGRAM_ID, "VERIFICATION_PROGRAM_ID missing/invalid");

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

    const provider = new AnchorProvider(connection, wallet as any, { commitment: "confirmed" });
    const program = await Program.at(programId, provider);

    const daoId = mustPubkey(daoIdStr, "payload.daoId missing/invalid");

    const [spacePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("space"), daoId.toBuffer()],
      programId
    );

    const [identityPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("identity"), spacePda.toBuffer(), Buffer.from([platformSeed]), Buffer.from(idHash)],
      programId
    );

    const [linkPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("link"), identityPda.toBuffer(), Buffer.from(walletHash)],
      programId
    );

    const expiresAt = new BN(0); // ✅ Anchor BN (no bn.js import)

    await (program as any).methods
      .attestIdentity(
        daoId,
        platformEnumObject(platform),
        platformSeed,
        Array.from(idHash),
        expiresAt
      )
      .accounts({
        spaceAcct: spacePda,
        attestor: kp.publicKey,
        identity: identityPda,
        payer: kp.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([kp])
      .rpc();

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
    return NextResponse.json(
      { error: String(e?.message || e), stack: e?.stack ? String(e.stack) : undefined },
      { status: 500 }
    );
  }
}