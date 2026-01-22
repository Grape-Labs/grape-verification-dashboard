import { NextResponse } from "next/server";
import crypto from "crypto";

export const runtime = "nodejs";

function parseCookies(cookieHeader: string) {
  const out: Record<string, string> = {};
  for (const part of cookieHeader.split(";")) {
    const p = part.trim();
    if (!p) continue;
    const i = p.indexOf("=");
    if (i === -1) continue;
    const k = p.slice(0, i);
    const v = p.slice(i + 1);
    out[k] = decodeURIComponent(v);
  }
  return out;
}

function b64url(buf: Buffer) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function signHmac(secret: string, data: string) {
  return b64url(crypto.createHmac("sha256", secret).update(data).digest());
}

export async function GET(req: Request) {
  const cookies = parseCookies(req.headers.get("cookie") || "");
  const discordId = cookies["gv_discord_id"] || "";
  if (!discordId) {
    return NextResponse.json({ connected: false }, { status: 200 });
  }

  const secret = process.env.DISCORD_PROOF_SECRET;
  if (!secret) {
    return NextResponse.json(
      { connected: true, error: "DISCORD_PROOF_SECRET missing (server misconfigured)" },
      { status: 500 }
    );
  }

  const now = Math.floor(Date.now() / 1000);
  const exp = now + 5 * 60;

  const header = { alg: "HS256", typ: "GV_DISCORD_PROOF" };
  const payload = { aud: "grape-verification", discordId, iat: now, exp };

  const h = b64url(Buffer.from(JSON.stringify(header)));
  const p = b64url(Buffer.from(JSON.stringify(payload)));
  const signingInput = `${h}.${p}`;
  const sig = signHmac(secret, signingInput);

  return NextResponse.json({
    connected: true,
    discordId,
    proof: `${signingInput}.${sig}`,
    exp,
  });
}