import { NextResponse } from "next/server";

export const runtime = "nodejs";

// ✅ Use global to share state between routes in Next.js
declare global {
  var emailVerificationCodes: Map<
    string,
    { code: string; email: string; expiresAt: number }
  > | undefined;
}

// Initialize once
if (!global.emailVerificationCodes) {
  global.emailVerificationCodes = new Map();

  // Clean up expired codes every 5 minutes
  setInterval(() => {
    if (!global.emailVerificationCodes) return;
    const now = Date.now();
    for (const [token, data] of global.emailVerificationCodes.entries()) {
      if (now > data.expiresAt) {
        global.emailVerificationCodes.delete(token);
      }
    }
  }, 5 * 60 * 1000);
}

function generateCode(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendVerificationEmail(email: string, code: string) {
  // TODO: Integrate with your email service (SendGrid, Resend, etc.)
  // For now, log to console (REMOVE IN PRODUCTION)
  console.log(`[EMAIL VERIFICATION] Email: ${email}, Code: ${code}`);
}

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const email = body.email?.trim().toLowerCase();

    if (!email) {
      return NextResponse.json({ error: "Email required" }, { status: 400 });
    }

    // Basic email validation
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return NextResponse.json({ error: "Invalid email" }, { status: 400 });
    }

    // Get token from cookie
    const cookieHeader = req.headers.get("cookie") || "";
    const cookies = Object.fromEntries(
      cookieHeader
        .split(";")
        .map((p) => p.trim())
        .filter(Boolean)
        .map((kv) => {
          const i = kv.indexOf("=");
          return [kv.slice(0, i), decodeURIComponent(kv.slice(i + 1))];
        })
    );

    const token = cookies["gv_email_token"];
    if (!token) {
      return NextResponse.json(
        { error: "No session token. Please refresh and try again." },
        { status: 400 }
      );
    }

    // Generate 6-digit code
    const code = generateCode();

    // Store code (expires in 10 minutes)
    global.emailVerificationCodes!.set(token, {
      code,
      email,
      expiresAt: Date.now() + 10 * 60 * 1000,
    });

    // Send email
    await sendVerificationEmail(email, code);

    return NextResponse.json({ ok: true });
  } catch (e: any) {
    console.error("[EMAIL] Send code error:", e);
    return NextResponse.json(
      { error: String(e?.message || e) },
      { status: 500 }
    );
  }
}