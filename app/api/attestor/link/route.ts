import { NextResponse } from "next/server";
import nacl from "tweetnacl";
import { Connection, Keypair, PublicKey, Transaction, SystemProgram } from "@solana/web3.js";

export const runtime = "nodejs";

const DEBUG = process.env.GV_DEBUG_ATTESTOR === "1";
function dbg(step: string, extra?: any) {
  if (!DEBUG) return;
  // eslint-disable-next-line no-console
  console.log(`[attestor/link] ${step}`, extra ?? "");
}

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
    const anchorMod: any = await import("@coral-xyz/anchor");

    // Anchor sometimes ends up under `.default` depending on bundler/runtime.
    const AnchorProvider = anchorMod.AnchorProvider ?? anchorMod.default?.AnchorProvider;
    const Program = anchorMod.Program ?? anchorMod.default?.Program;
    const BNClass = anchorMod.BN ?? anchorMod.default?.BN;

    if (!AnchorProvider || !Program) {
      throw new Error(
        "Anchor exports missing (AnchorProvider/Program). " +
          "Ensure this route runs in the Node.js runtime (runtime=nodejs) and that @coral-xyz/anchor is installed."
      );
    }

    // BN is sometimes not exported as expected in some builds; fall back to dynamic bn.js import.
    const BN: any = BNClass ?? (await import("bn.js").then((m: any) => m?.default ?? m));
    if (!BN) throw new Error("BN not available (anchor.BN or bn.js)");

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

    dbg("payload", { daoIdStr, platform, platformSeed, wallet: walletStr, ts });

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

    dbg("signature_ok", { wallet: walletPk.toBase58(), sigLen: sig.length });

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

    // ✅ Avoid Program.at() here.
    // In some Next.js/Turbopack runtimes, Program.at() can crash inside Anchor's translateAddress
    // when it tries to translate an undefined address from IDL metadata.
    // Fetch the IDL explicitly and construct the Program with an explicit programId.
    dbg("fetch_idl_start", { programId: programId.toBase58() });
    const idl = await (Program as any).fetchIdl(programId, provider);
    if (!idl) {
      throw new Error(
        "IDL not found on-chain for this program. " +
          "Ensure the program is deployed to the selected cluster and the IDL was uploaded."
      );
    }
    dbg("fetch_idl_ok", {
      hasMetadata: !!(idl as any)?.metadata,
      name: (idl as any)?.name,
      version: (idl as any)?.version,
    });

    const program = new (Program as any)(idl, programId, provider);
    if (!program) throw new Error("Program construction failed");

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

    dbg("pdas", {
      programId: programId.toBase58(),
      spacePda: spacePda.toBase58(),
      identityPda: identityPda.toBase58(),
      linkPda: linkPda.toBase58(),
    });

    const expiresAt = new BN(0); // i64 => BN
    dbg("expiresAt", { expiresAtType: typeof expiresAt, hasWords: !!(expiresAt as any)?.words });

    try {
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
    } catch (e: any) {
      dbg("attestIdentity_failed", { message: String(e?.message || e), stack: e?.stack });
      throw new Error(`attestIdentity failed: ${String(e?.message || e)}`);
    }

    try {
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
    } catch (e: any) {
      dbg("linkWallet_failed", { message: String(e?.message || e), stack: e?.stack });
      throw new Error(`linkWallet failed: ${String(e?.message || e)}`);
    }

    return NextResponse.json({
      ok: true,
      space: spacePda.toBase58(),
      identity: identityPda.toBase58(),
      link: linkPda.toBase58(),
      attestor: kp.publicKey.toBase58(),
    });
  } catch (e: any) {
    const message = String(e?.message || e);
    const stack = e?.stack ? String(e.stack) : undefined;

    return NextResponse.json(
      {
        error: message,
        ...(stack ? { stack } : {}),
        hint:
          message.includes("_bn")
            ? "A PublicKey/BN was undefined. Check that all env vars are set and that payload fields are valid; enable GV_DEBUG_ATTESTOR=1 to see step logs."
            : undefined,
      },
      { status: 500 }
    );
  }
}