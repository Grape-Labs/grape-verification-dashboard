import { NextResponse } from "next/server";
import nacl from "tweetnacl";
import crypto from "crypto";
import { Connection, Keypair, PublicKey, Transaction } from "@solana/web3.js";

import {
  PROGRAM_ID as REGISTRY_PROGRAM_ID,
  VerificationPlatform,
  identityHash,
  walletHash,
  TAG_DISCORD,
  TAG_TELEGRAM,
  TAG_TWITTER,
  TAG_EMAIL,
  buildAttestIdentityIx,
  buildLinkWalletIx,
  deriveSpacePda,
  deriveIdentityPda,
  deriveLinkPda,
} from "@grapenpm/grape-verification-registry";

export const runtime = "nodejs";

function dbg(...args: any[]) {
  if (process.env.GV_DEBUG_ATTESTOR === "1") {
    // eslint-disable-next-line no-console
    console.log("[attestor/link]", ...args);
  }
}

function b64url(buf: Buffer) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function b64urlToBuf(s: string) {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(b64, "base64");
}

function signHmac(secret: string, data: string) {
  return b64url(crypto.createHmac("sha256", secret).update(data).digest());
}

function parseSecretKey(sk: string): Uint8Array {
  const trimmed = (sk || "").trim();
  if (!trimmed) throw new Error("ATTESTOR_SECRET_KEY missing");

  // JSON array string: "[1,2,3,...]"
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    const arr = JSON.parse(trimmed);
    if (!Array.isArray(arr)) {
      throw new Error("ATTESTOR_SECRET_KEY must be a JSON array");
    }
    return Uint8Array.from(arr.map((n: any) => Number(n)));
  }

  // base64/base64url fallback
  try {
    const buf =
      trimmed.includes("-") || trimmed.includes("_")
        ? b64urlToBuf(trimmed)
        : Buffer.from(trimmed, "base64");
    if (buf.length > 0) return new Uint8Array(buf);
  } catch {
    // ignore
  }

  throw new Error(
    "ATTESTOR_SECRET_KEY format not recognized. Use JSON array or base64/base64url"
  );
}

function platformSeed(platform: string): number {
  switch (platform) {
    case "discord":
      return VerificationPlatform.Discord;
    case "telegram":
      return VerificationPlatform.Telegram;
    case "twitter":
      return VerificationPlatform.Twitter;
    case "email":
      return VerificationPlatform.Email;
    default:
      return VerificationPlatform.Discord;
  }
}

function platformTag(platform: string): string {
  switch (platform) {
    case "discord":
      return TAG_DISCORD;
    case "telegram":
      return TAG_TELEGRAM;
    case "twitter":
      return TAG_TWITTER;
    case "email":
      return TAG_EMAIL;
    default:
      return TAG_DISCORD;
  }
}

function bytesToHex(u8: Uint8Array) {
  return Array.from(u8)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Space struct offsets per your lib.rs
function parseSpaceSalt(data: Uint8Array): Uint8Array {
  // discriminator(8) + version(1) + dao(32) + authority(32) + attestor(32) + is_frozen(1) + bump(1) = 107
  const SALT_OFFSET = 8 + 1 + 32 + 32 + 32 + 1 + 1;
  return data.slice(SALT_OFFSET, SALT_OFFSET + 32);
}

function verifyDiscordProof(proof: string, secret: string) {
  const parts = (proof || "").split(".");
  if (parts.length !== 3) throw new Error("Invalid discord proof format");

  const signingInput = `${parts[0]}.${parts[1]}`;
  const expected = signHmac(secret, signingInput);
  if (expected !== parts[2]) throw new Error("Invalid discord proof signature");

  const payloadJson = b64urlToBuf(parts[1]).toString("utf8");
  const payload = JSON.parse(payloadJson);

  if (payload?.aud !== "grape-verification")
    throw new Error("Invalid discord proof audience");
  if (!payload?.discordId) throw new Error("Missing discordId in proof");

  const now = Math.floor(Date.now() / 1000);
  if (payload?.exp && now > Number(payload.exp))
    throw new Error("Discord proof expired");

  return { discordId: String(payload.discordId) };
}

function buildConsentMessage(p: {
  daoId: string;
  platform: string;
  idHashHex: string;
  wallet: string;
  walletHashHex: string;
  ts: number | string;
}) {
  return new TextEncoder().encode(
    `Grape Verification Link Request\n` +
      `daoId=${p.daoId}\n` +
      `platform=${p.platform}\n` +
      `idHash=${p.idHashHex}\n` +
      `wallet=${p.wallet}\n` +
      `walletHash=${p.walletHashHex}\n` +
      `ts=${p.ts}\n`
  );
}

function requireU8Array32(name: string, v: any): Uint8Array {
  const u8 =
    v instanceof Uint8Array ? v :
    Buffer.isBuffer(v) ? new Uint8Array(v) :
    null;

  if (!u8) throw new Error(`${name} must be Uint8Array/Buffer`);
  if (u8.length !== 32) throw new Error(`${name} must be 32 bytes (got ${u8.length})`);
  return u8;
}

export async function POST(req: Request) {
  try {

    console.log("got link request");
    const body = await req.json().catch(() => null);
    const payload = body?.payload;
    const signatureBase64 = body?.signatureBase64;

    if (!payload || typeof payload !== "object") {
      return NextResponse.json({ error: "Missing payload" }, { status: 400 });
    }
    if (!signatureBase64 || typeof signatureBase64 !== "string") {
      return NextResponse.json({ error: "Missing signatureBase64" }, { status: 400 });
    }

    const programIdStr = process.env.NEXT_PUBLIC_REGISTRY_PROGRAM_ID;
    const rpc = process.env.NEXT_PUBLIC_SOLANA_RPC || process.env.REACT_APP_RPC_ENDPOINT;
    const attestorSk = process.env.ATTESTOR_SECRET_KEY;
    const discordProofSecret = process.env.DISCORD_PROOF_SECRET;

    if (!rpc) return NextResponse.json({ error: "NEXT_PUBLIC_SOLANA_RPC missing" }, { status: 500 });
    if (!attestorSk) return NextResponse.json({ error: "ATTESTOR_SECRET_KEY missing" }, { status: 500 });

    const daoId = String(payload.daoId || payload.daoIdStr || "").trim();
    const platform = String(payload.platform || "discord").trim();
    const walletStr = String(payload.wallet || "").trim();
    const ts = payload.ts;

    if (!daoId) return NextResponse.json({ error: "payload.daoId missing" }, { status: 400 });
    if (!walletStr) return NextResponse.json({ error: "payload.wallet missing" }, { status: 400 });

    const platformProof = payload.platformProof ? String(payload.platformProof) : "";
    if (platform === "discord") {
      if (!discordProofSecret) {
        return NextResponse.json({ error: "DISCORD_PROOF_SECRET missing (cannot verify Discord proof)" }, { status: 500 });
      }
      if (!platformProof) {
        return NextResponse.json(
          {
            error: "payload.platformProof missing (connect Discord first)",
            hint: "Call /api/discord/proof after OAuth connect and include returned `proof` as payload.platformProof.",
          },
          { status: 400 }
        );
      }
    }

    const daoPk = new PublicKey(daoId);
    const walletPk = new PublicKey(walletStr);

    // Single source of truth: always use the program id baked into the registry package
    const programId = REGISTRY_PROGRAM_ID;

    // If you also set NEXT_PUBLIC_REGISTRY_PROGRAM_ID, ensure it matches the package.
    if (programIdStr && programIdStr !== programId.toBase58()) {
      return NextResponse.json(
        {
          error: "Program ID mismatch",
          env: programIdStr,
          package: programId.toBase58(),
          hint: "NEXT_PUBLIC_REGISTRY_PROGRAM_ID must match the PROGRAM_ID inside @grapenpm/grape-verification-registry. Rebuild/publish the package with the deployed program id, or update env to match.",
        },
        { status: 500 }
      );
    }

    const connection = new Connection(rpc, { commitment: "confirmed" });

    // --- Space PDA + salt (server truth) ---
    const [spacePda] = deriveSpacePda(daoPk);
    const spaceAcct = await connection.getAccountInfo(spacePda);
    if (!spaceAcct) {
      return NextResponse.json({ error: `Space account not found: ${spacePda.toBase58()}` }, { status: 400 });
    }
    const salt = parseSpaceSalt(spaceAcct.data);
    if (salt.length !== 32) {
      return NextResponse.json({ error: `Parsed salt length invalid: ${salt.length}` }, { status: 500 });
    }

    // platformUserId: discordId from proof (server truth)
    let platformUserId = String(payload.platformUserId || "").trim();
    if (platform === "discord") {
      const proof = verifyDiscordProof(platformProof, discordProofSecret!);
      platformUserId = proof.discordId;
    }
    if (!platformUserId) {
      return NextResponse.json({ error: "platformUserId missing" }, { status: 400 });
    }

    // Derive hashes (server truth)
    const idhRaw = identityHash(salt, platformTag(platform), platformUserId);
    const whRaw = walletHash(salt, walletPk);

    const idh = requireU8Array32("identityHash(idh)", idhRaw);
    const wh = requireU8Array32("walletHash(wh)", whRaw);

    const platform_seed = platformSeed(platform);

    // PDAs (server truth)
    const [identityPda] = deriveIdentityPda(spacePda, platform_seed, idh);
    const [linkPda] = deriveLinkPda(identityPda, wh);

    const idHashHex = bytesToHex(idh);
    const walletHashHex = bytesToHex(wh);

    dbg("payload", {
      daoId,
      platform,
      platform_seed,
      platformUserId,
      wallet: walletPk.toBase58(),
      ts: String(ts ?? ""),
    });
    dbg("pdas", {
      programId: programId.toBase58(),
      spacePda: spacePda.toBase58(),
      identityPda: identityPda.toBase58(),
      linkPda: linkPda.toBase58(),
    });

    // Verify wallet consent signature (off-chain)
    const message = buildConsentMessage({
      daoId,
      platform,
      idHashHex,
      wallet: walletPk.toBase58(),
      walletHashHex,
      ts: ts ?? "",
    });

    const sigBytes = Buffer.from(signatureBase64, "base64");
    if (sigBytes.length !== 64) {
      return NextResponse.json({ error: "signatureBase64 must decode to 64 bytes" }, { status: 400 });
    }

    const ok = nacl.sign.detached.verify(message, new Uint8Array(sigBytes), walletPk.toBytes());
    if (!ok) {
      return NextResponse.json({ error: "Invalid wallet signature" }, { status: 400 });
    }

    // Attestor (server) signs + pays
    const kp = Keypair.fromSecretKey(parseSecretKey(attestorSk));

    // Helpful early error if unfunded
    const bal = await connection.getBalance(kp.publicKey, "confirmed");
    dbg("attestor_balance", { feePayer: kp.publicKey.toBase58(), lamports: bal });
    if (bal < 5000) {
      return NextResponse.json(
        {
          error: "Attestor fee-payer has insufficient SOL",
          feePayer: kp.publicKey.toBase58(),
          lamports: bal,
          hint: "Fund ATTESTOR_SECRET_KEY pubkey on the same cluster as NEXT_PUBLIC_SOLANA_RPC (devnet vs mainnet).",
        },
        { status: 500 }
      );
    }

    // ✅ platform enum for attest_identity builder
    const platformEnum =
      platform === "telegram"
        ? VerificationPlatform.Telegram
        : platform === "twitter"
        ? VerificationPlatform.Twitter
        : platform === "email"
        ? VerificationPlatform.Email
        : VerificationPlatform.Discord;

    // No BigInt literal (0n) to avoid TS target issues
    const expiresAt = BigInt(0);

    // -----------------------------
    // ✅ Build instructions (raw builders)
    // -----------------------------
    let ix1, ix2;
    try {
      ix1 = buildAttestIdentityIx({
        daoId: daoPk,
        platform: platformEnum,
        platformSeed: platform_seed,
        idHash: idh,
        expiresAt,
        attestor: kp.publicKey,
        payer: kp.publicKey,
        programId,
      }).ix;
    } catch (e: any) {
      return NextResponse.json(
        {
          error: "buildAttestIdentityIx failed",
          detail: String(e?.message || e),
          debug: process.env.GV_DEBUG_ATTESTOR === "1" ? { platformEnum, platform_seed, idhLen: idh.length } : undefined,
        },
        { status: 500 }
      );
    }

    try {
      ix2 = buildLinkWalletIx({
        daoId: daoPk,
        platformSeed: platform_seed,
        idHash: idh,
        wallet: walletPk,
        walletHash: wh,
        attestor: kp.publicKey,
        payer: kp.publicKey,
        programId,
      }).ix;
    } catch (e: any) {
      return NextResponse.json(
        {
          error: "buildLinkWalletIx failed",
          detail: String(e?.message || e),
          debug:
            process.env.GV_DEBUG_ATTESTOR === "1"
              ? { platform_seed, idhLen: idh.length, whLen: wh.length, wallet: walletPk.toBase58() }
              : undefined,
        },
        { status: 500 }
      );
    }

    const tx = new Transaction().add(ix1, ix2);
    tx.feePayer = kp.publicKey;

    const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash("confirmed");
    tx.recentBlockhash = blockhash;
    tx.sign(kp);

    // ✅ Sim first (debug)
    const sim = await (connection as any).simulateTransaction(tx, {
      commitment: "processed",
      sigVerify: false,
    });

    if (sim?.value?.err) {
      return NextResponse.json(
        {
          error: "Simulation failed",
          simErr: sim.value.err,
          logs: sim.value.logs || [],
          derived: {
            spacePda: spacePda.toBase58(),
            identityPda: identityPda.toBase58(),
            linkPda: linkPda.toBase58(),
            idHashHex,
            walletHashHex,
            platformUserId,
            platform_seed,
          },
          hint:
            "Common causes: (1) space.attestor != ATTESTOR pubkey, (2) wrong cluster/RPC, (3) space not initialized / wrong DAO.",
        },
        { status: 500 }
      );
    }

    const sig = await connection.sendRawTransaction(tx.serialize(), {
      skipPreflight: false,
      maxRetries: 3,
    });

    await connection.confirmTransaction({ signature: sig, blockhash, lastValidBlockHeight }, "confirmed");

    return NextResponse.json({
      ok: true,
      signature: sig,
      identityPda: identityPda.toBase58(),
      linkPda: linkPda.toBase58(),
    });
  } catch (e: any) {
    return NextResponse.json(
      {
        error: String(e?.message || e),
        stack: process.env.GV_DEBUG_ATTESTOR === "1" ? String(e?.stack || "") : undefined,
      },
      { status: 500 }
    );
  }
}