import { NextResponse } from "next/server";
import nacl from "tweetnacl";
import crypto from "crypto";
import { Connection, Keypair, PublicKey, Transaction } from "@solana/web3.js";
import bs58 from "bs58";

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
  console.log("[attestor/link]", ...args);
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

  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    const arr = JSON.parse(trimmed);
    if (!Array.isArray(arr)) {
      throw new Error("ATTESTOR_SECRET_KEY must be a JSON array");
    }
    return Uint8Array.from(arr.map((n: any) => Number(n)));
  }

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

function resolveAttestorSecretKeyForDao(daoId: string): string | null {
  // 1) Vercel KV / Upstash per-DAO key
  // key format: attestor:key:<daoId> => {"secretKey":"..."}
  // This is async via REST, so this sync helper keeps env-only behavior.
  // The async KV lookup is done by `resolveAttestorSecretKeyForDaoAsync`.
  const rawMap = (process.env.ATTESTOR_SECRET_KEYS_BY_DAO || "").trim();
  if (rawMap) {
    try {
      const parsed: unknown = JSON.parse(rawMap);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        const rec = parsed as Record<string, unknown>;
        const selected = rec[daoId] ?? rec.default ?? rec["*"];

        if (typeof selected === "string" && selected.trim()) {
          return selected.trim();
        }

        if (selected && typeof selected === "object" && !Array.isArray(selected)) {
          const withKey = selected as Record<string, unknown>;
          const sk = withKey.secretKey;
          if (typeof sk === "string" && sk.trim()) {
            return sk.trim();
          }
        }
      }
    } catch (e) {
      dbg("Failed to parse ATTESTOR_SECRET_KEYS_BY_DAO:", e);
    }
  }

  const fallback = (process.env.ATTESTOR_SECRET_KEY || "").trim();
  return fallback || null;
}

async function resolveAttestorSecretKeyForDaoAsync(
  daoId: string
): Promise<string | null> {
  const kvUrl = (process.env.KV_REST_API_URL || "").trim();
  const kvToken = (process.env.KV_REST_API_TOKEN || "").trim();
  if (kvUrl && kvToken) {
    try {
      const key = `attestor:key:${daoId}`;
      const res = await fetch(`${kvUrl}/get/${encodeURIComponent(key)}`, {
        method: "GET",
        headers: { Authorization: `Bearer ${kvToken}` },
        cache: "no-store",
      });

      if (res.ok) {
        const payload = await res.json().catch(() => null);
        const result = payload?.result;
        if (result) {
          let parsed: unknown = result;
          if (typeof result === "string") {
            try {
              parsed = JSON.parse(result);
            } catch {
              parsed = null;
            }
          }

          if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
            const rec = parsed as Record<string, unknown>;
            const sk = rec.secretKey;
            if (typeof sk === "string" && sk.trim()) {
              return sk.trim();
            }
          }
        }
      }
    } catch (e) {
      dbg("KV attestor lookup failed:", e);
    }
  }

  return resolveAttestorSecretKeyForDao(daoId);
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

function parseSpaceSalt(data: Uint8Array): Uint8Array {
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
  // Canonical message format (must match what client signs)
  return new TextEncoder().encode(
    `Grape Verification Link Request\n` +
      `platform=${p.platform}\n` +
      `wallet=${p.wallet}\n` +
      `ts=${p.ts}`
  );
}

function requireU8Array32(name: string, v: any): Uint8Array {
  const u8 =
    v instanceof Uint8Array
      ? v
      : Buffer.isBuffer(v)
      ? new Uint8Array(v)
      : null;

  if (!u8) throw new Error(`${name} must be Uint8Array/Buffer`);
  if (u8.length !== 32)
    throw new Error(`${name} must be 32 bytes (got ${u8.length})`);
  return u8;
}

/**
 * Decode signature that might come as:
 * - base64
 * - base64url
 * - base58 (common in Solana)
 */
function decodeWalletSignature(sig: string): { bytes: Uint8Array; mode: string } {
  const s = (sig || "").trim();
  if (!s) throw new Error("Empty signature");

  if (s.includes("-") || s.includes("_")) {
    return { bytes: new Uint8Array(b64urlToBuf(s)), mode: "base64url" };
  }

  if (/[+/=]/.test(s)) {
    return { bytes: new Uint8Array(Buffer.from(s, "base64")), mode: "base64" };
  }

  return { bytes: new Uint8Array(bs58.decode(s)), mode: "base58" };
}

/**
 * Allow client to send exact message that was signed:
 * - body.message: plain UTF-8 string
 * - body.messageBase64: base64/base64url encoded UTF-8 bytes
 */
function parseClientMessage(body: any): Uint8Array | null {
  const msg = body?.message;
  if (typeof msg === "string" && msg.trim().length > 0) {
    return new TextEncoder().encode(msg);
  }

  const msgB64 = body?.messageBase64;
  if (typeof msgB64 === "string" && msgB64.trim().length > 0) {
    const s = msgB64.trim();
    const buf =
      s.includes("-") || s.includes("_") ? b64urlToBuf(s) : Buffer.from(s, "base64");
    return new Uint8Array(buf);
  }

  return null;
}

export async function POST(req: Request) {
  try {
    console.log("🚀 ========================================");
    console.log("🚀 [ATTESTOR] Link request received");
    console.log("🚀 ========================================");

    const body = await req.json().catch(() => null);
    const payload = body?.payload;
    const signatureBase64 = body?.signatureBase64;

    if (!payload || typeof payload !== "object") {
      return NextResponse.json({ error: "Missing payload" }, { status: 400 });
    }
    if (!signatureBase64 || typeof signatureBase64 !== "string") {
      return NextResponse.json(
        { error: "Missing signatureBase64" },
        { status: 400 }
      );
    }

    const programIdStr = REGISTRY_PROGRAM_ID;
    const rpc =
      process.env.NEXT_PUBLIC_SOLANA_RPC || process.env.REACT_APP_RPC_ENDPOINT;
    const discordProofSecret = process.env.DISCORD_PROOF_SECRET;

    if (!rpc)
      return NextResponse.json(
        { error: "NEXT_PUBLIC_SOLANA_RPC missing" },
        { status: 500 }
      );
    const daoId = String(payload.daoId || payload.daoIdStr || "").trim();
    const platform = String(payload.platform || "discord").trim();
    const walletStr = String(payload.wallet || "").trim();
    const ts = payload.ts;

    if (!daoId)
      return NextResponse.json(
        { error: "payload.daoId missing" },
        { status: 400 }
      );
    if (!walletStr)
      return NextResponse.json(
        { error: "payload.wallet missing" },
        { status: 400 }
      );

    const attestorSk = await resolveAttestorSecretKeyForDaoAsync(daoId);
    if (!attestorSk) {
      return NextResponse.json(
        {
          error: "No attestor secret configured for DAO",
          daoId,
          hint:
            "Set ATTESTOR_SECRET_KEYS_BY_DAO (preferred) or ATTESTOR_SECRET_KEY (fallback).",
        },
        { status: 500 }
      );
    }

    const platformProof = payload.platformProof
      ? String(payload.platformProof)
      : "";
    if (platform === "discord") {
      if (!discordProofSecret) {
        return NextResponse.json(
          {
            error: "DISCORD_PROOF_SECRET missing (cannot verify Discord proof)",
          },
          { status: 500 }
        );
      }
      if (!platformProof) {
        return NextResponse.json(
          {
            error: "payload.platformProof missing (connect Discord first)",
            hint:
              "Call /api/discord/proof after OAuth connect and include returned `proof` as payload.platformProof.",
          },
          { status: 400 }
        );
      }
    }

    const daoPk = new PublicKey(daoId);
    const walletPk = new PublicKey(walletStr);
    const programId = REGISTRY_PROGRAM_ID;

    console.log("📦 Program ID:", programId.toBase58());

    if (programIdStr && programIdStr.toBase58() !== programId.toBase58()) {
      return NextResponse.json(
        {
          error: "Program ID mismatch",
          env: programIdStr,
          package: programId.toBase58(),
          hint:
            "NEXT_PUBLIC_REGISTRY_PROGRAM_ID must match the PROGRAM_ID inside @grapenpm/grape-verification-registry.",
        },
        { status: 500 }
      );
    }

    const connection = new Connection(rpc, { commitment: "confirmed" });

    const [spacePda] = deriveSpacePda(daoPk);
    const spaceAcct = await connection.getAccountInfo(spacePda);
    if (!spaceAcct) {
      return NextResponse.json(
        { error: `Space account not found: ${spacePda.toBase58()}` },
        { status: 400 }
      );
    }

    const salt = parseSpaceSalt(spaceAcct.data);
    if (salt.length !== 32) {
      return NextResponse.json(
        { error: `Parsed salt length invalid: ${salt.length}` },
        { status: 500 }
      );
    }

    // Space layout: disc(8) + version(1) + dao_id(32) + authority(32) + attestor(32) + ...
    const ATTESTOR_OFFSET = 8 + 1 + 32 + 32; // = 73
    const spaceAttestorBytes = spaceAcct.data.slice(
      ATTESTOR_OFFSET,
      ATTESTOR_OFFSET + 32
    );
    const spaceAttestor = new PublicKey(spaceAttestorBytes);

    console.log("🔍 Space account check:");
    console.log("  - Space PDA:", spacePda.toBase58());
    console.log("  - Space.attestor (on-chain):", spaceAttestor.toBase58());

    let platformUserId = String(payload.platformUserId || "").trim();
    if (platform === "discord") {
      const proof = verifyDiscordProof(platformProof, discordProofSecret!);
      platformUserId = proof.discordId;
    }
    if (!platformUserId) {
      return NextResponse.json(
        { error: "platformUserId missing" },
        { status: 400 }
      );
    }

    const idhRaw = identityHash(salt, platformTag(platform), platformUserId);
    const whRaw = walletHash(salt, walletPk);

    const idh = requireU8Array32("identityHash(idh)", idhRaw);
    const wh = requireU8Array32("walletHash(wh)", whRaw);

    const platform_seed = platformSeed(platform);
    const [identityPda] = deriveIdentityPda(spacePda, platform_seed, idh);
    const [linkPda] = deriveLinkPda(identityPda, wh);

    const idHashHex = bytesToHex(idh);
    const walletHashHex = bytesToHex(wh);

    dbg("PDAs:", {
      space: spacePda.toBase58(),
      identity: identityPda.toBase58(),
      link: linkPda.toBase58(),
    });

    // Canonical message server expects
    const canonicalMsg = buildConsentMessage({
      daoId,
      platform,
      idHashHex,
      wallet: walletPk.toBase58(),
      walletHashHex,
      ts: ts ?? "",
    });

    // If client provided exact signed message, prefer that.
    const clientMsg = parseClientMessage(body);
    const messageToVerify = clientMsg ?? canonicalMsg;

    // Decode signature
    let sigDecoded: { bytes: Uint8Array; mode: string };
    try {
      sigDecoded = decodeWalletSignature(signatureBase64);
    } catch (e: any) {
      return NextResponse.json(
        {
          error: "Invalid signature encoding",
          detail: String(e?.message || e),
        },
        { status: 400 }
      );
    }

    const sigBytes = sigDecoded.bytes;

    if (sigBytes.length !== 64) {
      return NextResponse.json(
        { error: `Signature must be 64 bytes, got ${sigBytes.length}` },
        { status: 400 }
      );
    }

    // Verify (try client message first, then canonical as fallback)
    const okClientOrCanonical =
      nacl.sign.detached.verify(messageToVerify, sigBytes, walletPk.toBytes()) ||
      (clientMsg
        ? nacl.sign.detached.verify(canonicalMsg, sigBytes, walletPk.toBytes())
        : false);

    if (!okClientOrCanonical) {
      const canonicalText = new TextDecoder().decode(canonicalMsg);
      const clientText = clientMsg ? new TextDecoder().decode(clientMsg) : null;

      console.log("❌ Signature verify failed");
      console.log("🔏 canonical message:\n" + canonicalText);
      if (clientText) console.log("🔏 client message:\n" + clientText);
      console.log("🔏 sig mode:", sigDecoded.mode);

      return NextResponse.json(
        {
          error: "Invalid wallet signature",
          hint:
            "Client signed a different message than server expected. Fix by sending body.message (exact signed string) or matching canonical format.",
          debug: {
            sigMode: sigDecoded.mode,
            canonicalMessage: canonicalText,
            clientMessageProvided: !!clientMsg,
            clientMessage: clientText,
            wallet: walletPk.toBase58(),
            platform,
            ts,
          },
        },
        { status: 400 }
      );
    }

    // Continue as before
    const kp = Keypair.fromSecretKey(parseSecretKey(attestorSk));
    const bal = await connection.getBalance(kp.publicKey, "confirmed");

    console.log("💰 Attestor balance:", bal, "lamports");
    console.log("🔑 Our attestor key:", kp.publicKey.toBase58());

    if (!spaceAttestor.equals(kp.publicKey)) {
      console.log("❌ ATTESTOR MISMATCH!");
      console.log("  - Expected (from ATTESTOR_SECRET_KEY):", kp.publicKey.toBase58());
      console.log("  - Actual (from Space account):", spaceAttestor.toBase58());
      return NextResponse.json(
        {
          error: "Attestor key mismatch",
          expected: kp.publicKey.toBase58(),
          actual: spaceAttestor.toBase58(),
          hint:
            "The ATTESTOR_SECRET_KEY doesn't match the attestor set in the Space account. Either update the Space.attestor on-chain, or use the correct secret key.",
        },
        { status: 403 }
      );
    }

    console.log("✅ Attestor key matches!");

    if (bal < 5000) {
      return NextResponse.json(
        {
          error: "Attestor fee-payer has insufficient SOL",
          feePayer: kp.publicKey.toBase58(),
          lamports: bal,
        },
        { status: 500 }
      );
    }

    const platformEnum =
      platform === "telegram"
        ? VerificationPlatform.Telegram
        : platform === "twitter"
        ? VerificationPlatform.Twitter
        : platform === "email"
        ? VerificationPlatform.Email
        : VerificationPlatform.Discord;

    const expiresAt = BigInt(0);

    let ix1, ix2;
    try {
      const result1 = buildAttestIdentityIx({
        daoId: daoPk,
        platform: platformEnum,
        platformSeed: platform_seed,
        idHash: idh,
        expiresAt,
        attestor: kp.publicKey,
        payer: kp.publicKey,
        programId,
      });
      ix1 = result1.ix;
    } catch (e: any) {
      console.log("❌ buildAttestIdentityIx error:", e);
      return NextResponse.json(
        {
          error: "buildAttestIdentityIx failed",
          detail: String(e?.message || e),
        },
        { status: 500 }
      );
    }

    try {
      const result2 = buildLinkWalletIx({
        daoId: daoPk,
        platformSeed: platform_seed,
        idHash: idh,
        wallet: walletPk,
        walletHash: wh,
        attestor: kp.publicKey,
        payer: kp.publicKey,
        programId,
      });
      ix2 = result2.ix;
    } catch (e: any) {
      console.log("❌ buildLinkWalletIx error:", e);
      return NextResponse.json(
        {
          error: "buildLinkWalletIx failed",
          detail: String(e?.message || e),
        },
        { status: 500 }
      );
    }

    const tx = new Transaction().add(ix1, ix2);
    tx.feePayer = kp.publicKey;

    const { blockhash, lastValidBlockHeight } =
      await connection.getLatestBlockhash("confirmed");
    tx.recentBlockhash = blockhash;
    tx.sign(kp);

    let sim;
    try {
      sim = await connection.simulateTransaction(tx);
    } catch (simError: any) {
      return NextResponse.json(
        {
          error: "Simulation call failed",
          detail: simError.message,
        },
        { status: 500 }
      );
    }

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
        },
        { status: 500 }
      );
    }

    const sig = await connection.sendRawTransaction(tx.serialize(), {
      skipPreflight: false,
      maxRetries: 3,
    });

    await connection.confirmTransaction(
      { signature: sig, blockhash, lastValidBlockHeight },
      "confirmed"
    );

    return NextResponse.json({
      ok: true,
      signature: sig,
      identityPda: identityPda.toBase58(),
      linkPda: linkPda.toBase58(),
    });
  } catch (e: any) {
    console.log("❌ ERROR:", e);
    return NextResponse.json(
      {
        error: String(e?.message || e),
        stack: String(e?.stack || ""),
      },
      { status: 500 }
    );
  }
}
