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
  buildUnlinkWalletIx,
  deriveSpacePda,
  deriveIdentityPda,
  deriveLinkPda,
} from "@grapenpm/grape-verification-registry";

export const runtime = "nodejs";

function dbg(...args: any[]) {
  console.log("[attestor/unlink]", ...args);
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

function platformSeedNum(platform: string): number {
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

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, "");
  if (clean.length !== 64) throw new Error(`Expected 64 hex chars, got ${clean.length}`);
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
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

export async function POST(req: Request) {
  try {
    console.log("🚀 ========================================");
    console.log("🚀 [ATTESTOR] Unlink request received");
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

    const rpc =
      process.env.NEXT_PUBLIC_SOLANA_RPC ||
      process.env.REACT_APP_RPC_ENDPOINT;
    const attestorSk = process.env.ATTESTOR_SECRET_KEY;
    const discordProofSecret = process.env.DISCORD_PROOF_SECRET;

    if (!rpc)
      return NextResponse.json(
        { error: "NEXT_PUBLIC_SOLANA_RPC missing" },
        { status: 500 }
      );
    if (!attestorSk)
      return NextResponse.json(
        { error: "ATTESTOR_SECRET_KEY missing" },
        { status: 500 }
      );

    const daoId = String(payload.daoId || "").trim();
    const platform = String(payload.platform || "discord").trim();
    const walletStr = String(payload.wallet || "").trim();
    const targetWalletHashHex = String(payload.walletHashHex || "").trim();
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
    if (!targetWalletHashHex)
      return NextResponse.json(
        { error: "payload.walletHashHex missing" },
        { status: 400 }
      );

    // Verify platform proof
    const platformProof = payload.platformProof
      ? String(payload.platformProof)
      : "";
    if (platform === "discord") {
      if (!discordProofSecret) {
        return NextResponse.json(
          { error: "DISCORD_PROOF_SECRET missing" },
          { status: 500 }
        );
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
    const programId = REGISTRY_PROGRAM_ID;

    console.log("📦 Program ID:", programId.toBase58());

    const connection = new Connection(rpc, { commitment: "confirmed" });

    // Load space account and salt
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

    // Parse space attestor to verify it matches our key
    const ATTESTOR_OFFSET = 8 + 1 + 32 + 32; // = 73
    const spaceAttestorBytes = spaceAcct.data.slice(
      ATTESTOR_OFFSET,
      ATTESTOR_OFFSET + 32
    );
    const spaceAttestor = new PublicKey(spaceAttestorBytes);

    console.log("🔍 Space account check:");
    console.log("  - Space PDA:", spacePda.toBase58());
    console.log("  - Space.attestor (on-chain):", spaceAttestor.toBase58());

    // Resolve platform user ID (from proof or payload)
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

    // Derive identity hash and PDAs
    const idhRaw = identityHash(salt, platformTag(platform), platformUserId);
    const idh = requireU8Array32("identityHash(idh)", idhRaw);

    // The walletHash to unlink comes from the payload (could be any linked wallet, not just the connected one)
    const targetWh = hexToBytes(targetWalletHashHex);

    const platform_seed = platformSeedNum(platform);
    const [identityPda] = deriveIdentityPda(spacePda, platform_seed, idh);
    const [linkPda] = deriveLinkPda(identityPda, targetWh);

    const idHashHex = bytesToHex(idh);

    dbg("PDAs:", {
      space: spacePda.toBase58(),
      identity: identityPda.toBase58(),
      link: linkPda.toBase58(),
    });

    // Verify the link account actually exists on-chain
    const linkAcct = await connection.getAccountInfo(linkPda);
    if (!linkAcct) {
      return NextResponse.json(
        {
          error: "Link account not found on-chain",
          linkPda: linkPda.toBase58(),
          hint: "The wallet you're trying to unlink doesn't appear to be linked.",
        },
        { status: 400 }
      );
    }

    // Verify wallet signature on the consent message
    const message = new TextEncoder().encode(
      `Grape Verification Unlink Request\n` +
        `platform=${platform}\n` +
        `wallet=${walletPk.toBase58()}\n` +
        `walletHash=${targetWalletHashHex}\n` +
        `ts=${ts ?? ""}`
    );

    const sigBytes = Buffer.from(signatureBase64, "base64");
    if (sigBytes.length !== 64) {
      return NextResponse.json(
        { error: "signatureBase64 must decode to 64 bytes" },
        { status: 400 }
      );
    }

    const ok = nacl.sign.detached.verify(
      message,
      new Uint8Array(sigBytes),
      walletPk.toBytes()
    );
    if (!ok) {
      return NextResponse.json(
        { error: "Invalid wallet signature" },
        { status: 400 }
      );
    }

    // Load attestor keypair and verify it matches on-chain
    const kp = Keypair.fromSecretKey(parseSecretKey(attestorSk));
    const bal = await connection.getBalance(kp.publicKey, "confirmed");

    console.log("💰 Attestor balance:", bal, "lamports");
    console.log("🔑 Our attestor key:", kp.publicKey.toBase58());

    if (!spaceAttestor.equals(kp.publicKey)) {
      console.log("❌ ATTESTOR MISMATCH!");
      return NextResponse.json(
        {
          error: "Attestor key mismatch",
          expected: kp.publicKey.toBase58(),
          actual: spaceAttestor.toBase58(),
          hint: "The ATTESTOR_SECRET_KEY doesn't match the attestor set in the Space account.",
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

    // Build the unlink instruction
    // recipient receives the rent from the closed link account — send it to the attestor (fee payer)
    let unlinkIx;
    try {
      const result = buildUnlinkWalletIx({
        daoId: daoPk,
        platformSeed: platform_seed,
        idHash: idh,
        walletHash: targetWh,
        attestor: kp.publicKey,
        recipient: kp.publicKey, // rent goes back to attestor
        programId,
      });
      unlinkIx = result.ix;

      console.log("📏 unlink_wallet data length:", unlinkIx.data.length);
      console.log("✅ Expected: 105 bytes");
      console.log(
        "🎯 Match:",
        unlinkIx.data.length === 105 ? "YES ✅" : "NO ❌"
      );
    } catch (e: any) {
      console.log("❌ buildUnlinkWalletIx error:", e);
      return NextResponse.json(
        {
          error: "buildUnlinkWalletIx failed",
          detail: String(e?.message || e),
        },
        { status: 500 }
      );
    }

    console.log("✅ Unlink instruction built successfully");

    // Build, sign, simulate, and send the transaction
    const tx = new Transaction().add(unlinkIx);
    tx.feePayer = kp.publicKey;

    const { blockhash, lastValidBlockHeight } =
      await connection.getLatestBlockhash("confirmed");
    tx.recentBlockhash = blockhash;
    tx.sign(kp);

    console.log("🔍 Running simulation...");

    let sim;
    try {
      sim = await connection.simulateTransaction(tx);
    } catch (simError: any) {
      console.log("❌ Simulation call failed:", simError.message);
      return NextResponse.json(
        {
          error: "Simulation call failed",
          detail: simError.message,
        },
        { status: 500 }
      );
    }

    console.log(
      "🔍 Simulation result:",
      sim?.value?.err ? "FAILED ❌" : "SUCCESS ✅"
    );

    if (sim?.value?.err) {
      console.log("❌ Program simulation failed!");
      console.log("Error object:", JSON.stringify(sim.value.err, null, 2));
      console.log("📋 Program logs:");
      (sim.value.logs || []).forEach((log: string) => console.log("  ", log));

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
            walletHashHex: targetWalletHashHex,
            platformUserId,
            platform_seed,
          },
        },
        { status: 500 }
      );
    }

    console.log("✅ Simulation passed!");

    const sig = await connection.sendRawTransaction(tx.serialize(), {
      skipPreflight: false,
      maxRetries: 3,
    });

    console.log("✅ Transaction sent:", sig);

    await connection.confirmTransaction(
      { signature: sig, blockhash, lastValidBlockHeight },
      "confirmed"
    );

    console.log("✅ Transaction confirmed! Wallet unlinked.");

    return NextResponse.json({
      ok: true,
      signature: sig,
      unlinkedWalletHash: targetWalletHashHex,
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