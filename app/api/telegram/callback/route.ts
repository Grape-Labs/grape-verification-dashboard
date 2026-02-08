import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";

interface TelegramAuthData {
  id: number;
  first_name: string;
  last_name?: string;
  username?: string;
  photo_url?: string;
  auth_date: number;
  hash: string;
}

function verifyTelegramAuth(data: TelegramAuthData, botToken: string): boolean {
  const { hash, ...checkData } = data;

  // Create data check string
  const dataCheckString = Object.keys(checkData)
    .sort()
    .map((key) => `${key}=${(checkData as any)[key]}`)
    .join("\n");

  // Create secret key from bot token
  const secretKey = crypto.createHash("sha256").update(botToken).digest();

  // Create hash
  const hmac = crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  return hmac === hash;
}

export async function POST(req: NextRequest) {
  try {
    const authData: TelegramAuthData = await req.json();
    const botToken = process.env.TELEGRAM_BOT_TOKEN;

    if (!botToken) {
      return NextResponse.json(
        { error: "TELEGRAM_BOT_TOKEN not configured" },
        { status: 500 }
      );
    }

    // Verify Telegram data authenticity
    const isValid = verifyTelegramAuth(authData, botToken);
    if (!isValid) {
      return NextResponse.json(
        { error: "Invalid Telegram authentication data" },
        { status: 403 }
      );
    }

    // Check auth is recent (within 24 hours)
    const now = Math.floor(Date.now() / 1000);
    if (now - authData.auth_date > 86400) {
      return NextResponse.json(
        { error: "Authentication data is too old" },
        { status: 403 }
      );
    }

    // Store in session
    const session = {
      connected: true,
      id: authData.id,
      firstName: authData.first_name,
      lastName: authData.last_name,
      username: authData.username,
      photoUrl: authData.photo_url,
      authDate: authData.auth_date,
    };

    const response = NextResponse.json({ success: true, session });

    // Set session cookie
    response.cookies.set(
      "telegram_session",
      JSON.stringify(session),
      {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 60 * 60 * 24 * 30, // 30 days
      }
    );

    return response;
  } catch (e: any) {
    console.error("Telegram callback error:", e);
    return NextResponse.json(
      { error: String(e?.message || e) },
      { status: 500 }
    );
  }
}