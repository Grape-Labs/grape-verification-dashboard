import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";

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

export async function GET(req: NextRequest) {
  const sessionCookie = req.cookies.get("telegram_session");
  const secret = process.env.TELEGRAM_PROOF_SECRET;

  if (!secret) {
    return NextResponse.json(
      { error: "TELEGRAM_PROOF_SECRET not configured" },
      { status: 500 }
    );
  }

  if (!sessionCookie) {
    return NextResponse.json({ connected: false, proof: null });
  }

  try {
    const session = JSON.parse(sessionCookie.value);

    // Create JWT-style proof
    const header = { alg: "HS256", typ: "JWT" };
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      aud: "grape-verification",
      telegramId: String(session.id),
      username: session.username || null,
      verified: true,
      iat: now,
      exp: now + 60 * 60, // 1 hour
    };

    const headerB64 = b64url(Buffer.from(JSON.stringify(header)));
    const payloadB64 = b64url(Buffer.from(JSON.stringify(payload)));
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = signHmac(secret, signingInput);

    const proof = `${signingInput}.${signature}`;

    return NextResponse.json({
      connected: true,
      proof,
      telegramId: session.id,
      username: session.username,
    });
  } catch (e) {
    console.error("Telegram proof error:", e);
    return NextResponse.json({ connected: false, proof: null });
  }
}