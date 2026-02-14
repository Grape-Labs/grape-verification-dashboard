import { NextResponse } from "next/server";
import nacl from "tweetnacl";
import bs58 from "bs58";
import { Connection, PublicKey } from "@solana/web3.js";

import { deriveSpacePda } from "@grapenpm/grape-verification-registry";

export const runtime = "nodejs";

type StoredDiscordRoleConfig = {
  guildId: string;
  verifiedRoleId: string;
  enabled: boolean;
  updatedAt: string;
  updatedBy: string;
};

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

function isDiscordSnowflake(value: string): boolean {
  return /^\d{17,22}$/.test(value.trim());
}

function parseSpaceAuthority(data: Uint8Array): PublicKey {
  // disc(8) + version(1) + dao_id(32) + authority(32)
  const AUTHORITY_OFFSET = 8 + 1 + 32;
  return new PublicKey(data.slice(AUTHORITY_OFFSET, AUTHORITY_OFFSET + 32));
}

function keyForDao(daoId: string) {
  return `discord:role-config:${daoId}`;
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

function buildRoleConfigMessage(p: {
  daoId: string;
  wallet: string;
  guildId: string;
  verifiedRoleId: string;
  enabled: boolean;
  ts: string | number;
}) {
  return (
    "Grape Discord Role Config Save\n" +
    `daoId=${p.daoId}\n` +
    `wallet=${p.wallet}\n` +
    `guildId=${p.guildId}\n` +
    `verifiedRoleId=${p.verifiedRoleId}\n` +
    `enabled=${p.enabled ? "1" : "0"}\n` +
    `ts=${p.ts ?? ""}`
  );
}

function parseStoredConfig(entry: unknown): StoredDiscordRoleConfig | null {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return null;
  const rec = entry as Record<string, unknown>;
  const guildId =
    typeof rec.guildId === "string" && rec.guildId.trim() ? rec.guildId.trim() : null;
  const verifiedRoleId =
    typeof rec.verifiedRoleId === "string" && rec.verifiedRoleId.trim()
      ? rec.verifiedRoleId.trim()
      : null;
  if (!guildId || !verifiedRoleId) return null;

  return {
    guildId,
    verifiedRoleId,
    enabled: rec.enabled !== false,
    updatedAt:
      typeof rec.updatedAt === "string" && rec.updatedAt.trim()
        ? rec.updatedAt
        : "",
    updatedBy:
      typeof rec.updatedBy === "string" && rec.updatedBy.trim()
        ? rec.updatedBy
        : "",
  };
}

export async function GET(req: Request) {
  try {
    const { searchParams } = new URL(req.url);
    const daoId = (searchParams.get("daoId") || "").trim();
    if (!daoId) {
      return NextResponse.json({ error: "daoId is required" }, { status: 400 });
    }

    const entry = await kvGetJson(keyForDao(daoId));
    const parsed = parseStoredConfig(entry);
    if (!parsed) {
      return NextResponse.json({ ok: true, exists: false, daoId });
    }

    return NextResponse.json({
      ok: true,
      exists: true,
      daoId,
      guildId: parsed.guildId,
      verifiedRoleId: parsed.verifiedRoleId,
      enabled: parsed.enabled,
      updatedAt: parsed.updatedAt || null,
      updatedBy: parsed.updatedBy || null,
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
    const guildId = String(body?.guildId || "").trim();
    const verifiedRoleId = String(body?.verifiedRoleId || "").trim();
    const enabled = body?.enabled !== false;
    const ts = body?.ts ?? "";
    const message = String(body?.message || "").trim();
    const signatureBase64 = String(body?.signatureBase64 || "").trim();

    if (!daoId) {
      return NextResponse.json({ error: "daoId is required" }, { status: 400 });
    }
    if (!walletStr) {
      return NextResponse.json({ error: "wallet is required" }, { status: 400 });
    }
    if (!signatureBase64) {
      return NextResponse.json(
        { error: "signatureBase64 is required" },
        { status: 400 }
      );
    }
    if (!guildId || !isDiscordSnowflake(guildId)) {
      return NextResponse.json(
        { error: "guildId must be a valid Discord snowflake id" },
        { status: 400 }
      );
    }
    if (!verifiedRoleId || !isDiscordSnowflake(verifiedRoleId)) {
      return NextResponse.json(
        { error: "verifiedRoleId must be a valid Discord snowflake id" },
        { status: 400 }
      );
    }

    const walletPk = new PublicKey(walletStr);
    const daoPk = new PublicKey(daoId);
    const canonicalMessage = buildRoleConfigMessage({
      daoId,
      wallet: walletPk.toBase58(),
      guildId,
      verifiedRoleId,
      enabled,
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
        { error: "Invalid wallet signature for Discord role config update" },
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
    if (!authority.equals(walletPk)) {
      return NextResponse.json(
        {
          error: "Only space authority can update Discord role config",
          authority: authority.toBase58(),
          wallet: walletPk.toBase58(),
        },
        { status: 403 }
      );
    }

    const entry: StoredDiscordRoleConfig = {
      guildId,
      verifiedRoleId,
      enabled,
      updatedAt: new Date().toISOString(),
      updatedBy: walletPk.toBase58(),
    };

    await kvSetJson(keyForDao(daoId), entry);

    return NextResponse.json({
      ok: true,
      exists: true,
      daoId,
      guildId: entry.guildId,
      verifiedRoleId: entry.verifiedRoleId,
      enabled: entry.enabled,
      updatedAt: entry.updatedAt,
      updatedBy: entry.updatedBy,
    });
  } catch (e: any) {
    return NextResponse.json(
      { error: String(e?.message || e) },
      { status: 500 }
    );
  }
}
