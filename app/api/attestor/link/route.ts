import { NextResponse } from "next/server";
import nacl from "tweetnacl";
import * as anchor from "@coral-xyz/anchor";
import { Connection, Keypair, PublicKey } from "@solana/web3.js";

import {
  deriveSpacePda,
  deriveIdentityPda,
  deriveLinkPda,
  identityHash,
  walletHash,
  VerificationPlatform,
  TAG_DISCORD,
} from "@grapenpm/grape-verification-registry";

export const runtime = "nodejs";

/**
 * Space account layout (yours):
 * disc(8)
 * version(1)
 * dao_id(32)
 * authority(32)
 * attestor(32)
 * is_frozen(1)
 * bump(1)
 * salt(32)
 */
function parseSpaceSalt(data: Uint8Array): Uint8Array {
  const SALT_OFFSET = 8 + 1 + 32 + 32 + 32 + 1 + 1; // 107
  return data.slice(SALT_OFFSET, SALT_OFFSET + 32);
}

function bytesToHex(u8: Uint8Array) {
  return Array.from(u8).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function b64ToU8(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

function parseCookies(header: string) {
  return Object.fromEntries(
    header
      .split(";")
      .map((p) => p.trim())
      .filter(Boolean)
      .map((kv) => {
        const i = kv.indexOf("=");
        return [kv.slice(0, i), decodeURIComponent(kv.slice(i + 1))];
      })
  );
}

function loadAttestorKeypair(): Keypair {
  const raw = process.env.ATTESTOR_SECRET_KEY;
  if (!raw) throw new Error("ATTESTOR_SECRET_KEY missing");

  const s = raw.trim();
  if (s.startsWith("[")) {
    const arr = JSON.parse(s);
    return Keypair.fromSecretKey(Uint8Array.from(arr));
  }
  return Keypair.fromSecretKey(Buffer.from(s, "base64"));
}

// Must match EXACTLY what your client signs
function buildConsentMessage(payload: any) {
  return new TextEncoder().encode(
    `Grape Verification Link Request\n` +
      `daoId=${payload.daoId}\n` +
      `platform=${payload.platform}\n` +
      `idHash=${payload.idHashHex}\n` +
      `wallet=${payload.wallet}\n` +
      `walletHash=${payload.walletHashHex}\n` +
      `ts=${payload.ts}\n`
  );
}

// Anchor enum for your VerificationPlatform
function anchorPlatform(platform: string) {
  switch (platform) {
    case "discord":
      return { discord: {} };
    case "telegram":
      return { telegram: {} };
    case "twitter":
      return { twitter: {} };
    case "email":
      return { email: {} };
    default:
      return { discord: {} };
  }
}

export async function POST(req: Request) {
  try {
    const rpc = process.env.SOLANA_RPC_URL || "https://api.devnet.solana.com";
    const connection = new Connection(rpc, "confirmed");

    const programIdStr = process.env.VERIFICATION_PROGRAM_ID;
    if (!programIdStr) {
      return NextResponse.json({ error: "VERIFICATION_PROGRAM_ID missing" }, { status: 500 });
    }
    const programId = new PublicKey(programIdStr);

    // --- discord session cookie (source of truth) ---
    const cookieHeader = req.headers.get("cookie") || "";
    const cookies = parseCookies(cookieHeader);

    const discordId = cookies["gv_discord_id"];
    if (!discordId) {
      return NextResponse.json(
        { error: "Discord not connected (gv_discord_id cookie missing)" },
        { status: 401 }
      );
    }

    // --- body: { payload, signatureBase64 } ---
    const { payload, signatureBase64 } = await req.json();

    if (!payload || !signatureBase64) {
      return NextResponse.json({ error: "Missing payload/signatureBase64" }, { status: 400 });
    }

    // Only discord for now (keep simple)
    if (payload.platform !== "discord") {
      return NextResponse.json({ error: "Only discord supported on this route" }, { status: 400 });
    }

    const daoPk = new PublicKey(payload.daoId);
    const walletPk = new PublicKey(payload.wallet);

    // --- load Space + salt (do NOT trust client) ---
    const [spacePda] = deriveSpacePda(daoPk);
    const spaceAcct = await connection.getAccountInfo(spacePda);
    if (!spaceAcct) {
      return NextResponse.json({ error: "Space not found", space: spacePda.toBase58() }, { status: 400 });
    }
    const salt = parseSpaceSalt(spaceAcct.data);

    // --- recompute hashes from salt + cookie discord id ---
    const idh = identityHash(salt, TAG_DISCORD, String(discordId));
    const idHashHex = bytesToHex(idh);

    const wh = walletHash(salt, walletPk);
    const walletHashHex = bytesToHex(wh);

    // --- ensure payload hashes match (anti-spoof) ---
    if (String(payload.idHashHex || "").toLowerCase() !== idHashHex.toLowerCase()) {
      return NextResponse.json(
        { error: "idHash mismatch", payload: payload.idHashHex, server: idHashHex },
        { status: 400 }
      );
    }
    if (String(payload.walletHashHex || "").toLowerCase() !== walletHashHex.toLowerCase()) {
      return NextResponse.json(
        { error: "walletHash mismatch", payload: payload.walletHashHex, server: walletHashHex },
        { status: 400 }
      );
    }

    // --- verify wallet signature (user consent) ---
    const msgBytes = buildConsentMessage({ ...payload, idHashHex, walletHashHex });
    const sig = b64ToU8(signatureBase64);

    const ok = nacl.sign.detached.verify(msgBytes, sig, walletPk.toBytes());
    if (!ok) {
      return NextResponse.json({ error: "Invalid wallet signature" }, { status: 401 });
    }

    // --- derive PDAs ---
    const platformSeed = VerificationPlatform.Discord; // 0
    const [identityPda] = deriveIdentityPda(spacePda, platformSeed, idh);
    const [linkPda] = deriveLinkPda(identityPda, wh);

    // --- attestor signer (must match space.attestor on-chain) ---
    const attestorKp = loadAttestorKeypair();

    const provider = new anchor.AnchorProvider(
      connection,
      new anchor.Wallet(attestorKp),
      { commitment: "confirmed" }
    );

    // ✅ your preferred pattern: fetch IDL from chain
    const program = await anchor.Program.at(programId, provider);

    // 1) attest_identity (idempotent via init_if_needed)
    // fn attest_identity(ctx, _dao_id: Pubkey, platform: VerificationPlatform, platform_seed: u8, id_hash: [u8;32], expires_at: i64)
    const expiresAt = new anchor.BN(0); // no expiry for MVP

    const tx1 = await (program as any).methods
      .attestIdentity(daoPk, anchorPlatform("discord"), platformSeed, Array.from(idh), expiresAt)
      .accounts({
        spaceAcct: spacePda,
        attestor: attestorKp.publicKey,
        identity: identityPda,
        payer: attestorKp.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    // 2) link_wallet (idempotent via init_if_needed)
    // fn link_wallet(ctx, _dao_id: Pubkey, wallet_hash: [u8;32])
    const tx2 = await (program as any).methods
      .linkWallet(daoPk, Array.from(wh))
      .accounts({
        spaceAcct: spacePda,
        attestor: attestorKp.publicKey,
        identity: identityPda,
        wallet: walletPk, // unchecked on-chain; used for wallet_hash validation
        link: linkPda,
        payer: attestorKp.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    return NextResponse.json({
      ok: true,
      discordId,
      space: spacePda.toBase58(),
      identity: identityPda.toBase58(),
      link: linkPda.toBase58(),
      txAttestIdentity: tx1,
      txLinkWallet: tx2,
    });
  } catch (e: any) {
    return NextResponse.json({ error: String(e?.message || e) }, { status: 500 });
  }
}