import { NextResponse } from "next/server";
import nacl from "tweetnacl";
import bs58 from "bs58";
import { Connection, Keypair, PublicKey } from "@solana/web3.js";

import { deriveSpacePda } from "@grapenpm/grape-verification-registry";

export const runtime = "nodejs";

function parseSecretKey(sk: string): Uint8Array {
  const trimmed = (sk || "").trim();
  if (!trimmed) throw new Error("Attestor secret key missing");

  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    const arr = JSON.parse(trimmed);
    if (!Array.isArray(arr)) {
      throw new Error("Attestor secret key JSON must be an array");
    }
    return Uint8Array.from(arr.map((n: unknown) => Number(n)));
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
    "Attestor secret key format not recognized. Use JSON array or base64/base64url"
  );
}

function b64urlToBuf(s: string) {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(b64, "base64");
}

function decodeWalletSignature(sig: string): Uint8Array {
  const s = (sig || "").trim();
  if (!s) throw new Error("Empty signature");

  if (s.includes("-") || s.includes("_")) {
    return new Uint8Array(b64urlToBuf(s));
  }
  if (/[+/=]/.test(s)) {
    return new Uint8Array(Buffer.from(s, "base64"));
  }
  return new Uint8Array(bs58.decode(s));
}

function parseSpaceAuthority(data: Uint8Array): PublicKey {
  // disc(8) + version(1) + dao_id(32) + authority(32)
  const AUTHORITY_OFFSET = 8 + 1 + 32;
  return new PublicKey(data.slice(AUTHORITY_OFFSET, AUTHORITY_OFFSET + 32));
}

function parseSpaceAttestor(data: Uint8Array): PublicKey {
  // disc(8) + version(1) + dao_id(32) + authority(32) + attestor(32)
  const ATTESTOR_OFFSET = 8 + 1 + 32 + 32;
  return new PublicKey(data.slice(ATTESTOR_OFFSET, ATTESTOR_OFFSET + 32));
}

function keyForDao(daoId: string) {
  return `attestor:key:${daoId}`;
}

async function kvGetJson(key: string): Promise<unknown | null> {
  const url = (process.env.KV_REST_API_URL || "").trim();
  const token = (process.env.KV_REST_API_TOKEN || "").trim();
  if (!url || !token) return null;

  const res = await fetch(`${url}/get/${encodeURIComponent(key)}`, {
    method: "GET",
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  if (!res.ok) return null;

  const payload = await res.json().catch(() => null);
  const result = payload?.result;
  if (!result) return null;

  if (typeof result === "string") {
    try {
      return JSON.parse(result);
    } catch {
      return null;
    }
  }

  if (typeof result === "object") return result;
  return null;
}

async function kvSetJson(key: string, value: unknown): Promise<void> {
  const url = (process.env.KV_REST_API_URL || "").trim();
  const token = (process.env.KV_REST_API_TOKEN || "").trim();
  if (!url || !token) {
    throw new Error("KV_REST_API_URL / KV_REST_API_TOKEN are not configured");
  }

  const raw = JSON.stringify(value);
  const res = await fetch(
    `${url}/set/${encodeURIComponent(key)}/${encodeURIComponent(raw)}`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    }
  );

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`KV set failed (${res.status}): ${text || "unknown error"}`);
  }
}

function buildAdminMessage(p: { daoId: string; wallet: string; ts: string | number }) {
  return (
    "Grape Attestor Key Save\n" +
    `daoId=${p.daoId}\n` +
    `wallet=${p.wallet}\n` +
    `ts=${p.ts ?? ""}`
  );
}

export async function GET(req: Request) {
  try {
    const { searchParams } = new URL(req.url);
    const daoId = (searchParams.get("daoId") || "").trim();
    if (!daoId) {
      return NextResponse.json({ error: "daoId is required" }, { status: 400 });
    }

    const entry = await kvGetJson(keyForDao(daoId));
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      return NextResponse.json({ ok: true, exists: false });
    }

    const rec = entry as Record<string, unknown>;
    const secretKey =
      typeof rec.secretKey === "string" && rec.secretKey.trim()
        ? rec.secretKey.trim()
        : null;
    if (!secretKey) {
      return NextResponse.json({ ok: true, exists: false });
    }

    const kp = Keypair.fromSecretKey(parseSecretKey(secretKey));
    return NextResponse.json({
      ok: true,
      exists: true,
      daoId,
      attestorPubkey: kp.publicKey.toBase58(),
      updatedAt:
        typeof rec.updatedAt === "string" ? rec.updatedAt : null,
      updatedBy:
        typeof rec.updatedBy === "string" ? rec.updatedBy : null,
    });
  } catch (e: any) {
    return NextResponse.json(
      { error: String(e?.message || e) },
      { status: 500 }
    );
  }
}

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => null);
    const daoId = String(body?.daoId || "").trim();
    const walletStr = String(body?.wallet || "").trim();
    const attestorSecretKey = String(body?.attestorSecretKey || "").trim();
    const ts = body?.ts ?? "";
    const message = String(body?.message || "").trim();
    const signatureBase64 = String(body?.signatureBase64 || "").trim();

    if (!daoId) {
      return NextResponse.json({ error: "daoId is required" }, { status: 400 });
    }
    if (!walletStr) {
      return NextResponse.json({ error: "wallet is required" }, { status: 400 });
    }
    if (!attestorSecretKey) {
      return NextResponse.json(
        { error: "attestorSecretKey is required" },
        { status: 400 }
      );
    }
    if (!signatureBase64) {
      return NextResponse.json(
        { error: "signatureBase64 is required" },
        { status: 400 }
      );
    }

    const walletPk = new PublicKey(walletStr);
    const daoPk = new PublicKey(daoId);
    const canonicalMessage = buildAdminMessage({
      daoId,
      wallet: walletPk.toBase58(),
      ts,
    });
    const msgBytes = new TextEncoder().encode(message || canonicalMessage);
    const canonicalBytes = new TextEncoder().encode(canonicalMessage);
    const sigBytes = decodeWalletSignature(signatureBase64);

    const sigOk =
      nacl.sign.detached.verify(msgBytes, sigBytes, walletPk.toBytes()) ||
      (message
        ? nacl.sign.detached.verify(canonicalBytes, sigBytes, walletPk.toBytes())
        : false);
    if (!sigOk) {
      return NextResponse.json(
        { error: "Invalid wallet signature for admin attestor key update" },
        { status: 403 }
      );
    }

    const rpc =
      process.env.NEXT_PUBLIC_SOLANA_RPC || process.env.REACT_APP_RPC_ENDPOINT;
    if (!rpc) {
      return NextResponse.json(
        { error: "NEXT_PUBLIC_SOLANA_RPC missing" },
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

    const authority = parseSpaceAuthority(spaceAcct.data);
    const onChainAttestor = parseSpaceAttestor(spaceAcct.data);
    if (!authority.equals(walletPk)) {
      return NextResponse.json(
        {
          error: "Only space authority can store attestor key",
          authority: authority.toBase58(),
          wallet: walletPk.toBase58(),
        },
        { status: 403 }
      );
    }

    const kp = Keypair.fromSecretKey(parseSecretKey(attestorSecretKey));

    const entry = {
      secretKey: attestorSecretKey,
      attestorPubkey: kp.publicKey.toBase58(),
      updatedAt: new Date().toISOString(),
      updatedBy: walletPk.toBase58(),
      matchesOnChainAttestor: kp.publicKey.equals(onChainAttestor),
    };
    await kvSetJson(keyForDao(daoId), entry);

    return NextResponse.json({
      ok: true,
      daoId,
      attestorPubkey: kp.publicKey.toBase58(),
      matchesOnChainAttestor: entry.matchesOnChainAttestor,
    });
  } catch (e: any) {
    return NextResponse.json(
      { error: String(e?.message || e) },
      { status: 500 }
    );
  }
}
