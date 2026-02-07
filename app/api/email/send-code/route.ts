import { NextResponse } from "next/server";
import { Resend } from "resend";

export const runtime = "nodejs";

const resend = new Resend(process.env.RESEND_API_KEY);

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
  try {
    const { data, error } = await resend.emails.send({
      from: "Grape Verification <noreply@verification.governance.so>", // ✅ Must use verified domain
      to: email,
      subject: "Your Verification Code",
      html: `
        <div style="font-family: system-ui, -apple-system, sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #7c4dff;">Grape Verification</h1>
          <p>Your verification code is:</p>
          <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #333;">
            ${code}
          </div>
          <p style="color: #666; margin-top: 20px;">This code will expire in 10 minutes.</p>
          <p style="color: #999; font-size: 12px; margin-top: 40px;">If you didn't request this code, please ignore this email.</p>
        </div>
      `,
    });

    if (error) {
      console.error("[EMAIL] Resend error:", error);
      throw new Error(`Failed to send email: ${error.message}`);
    }

    console.log("[EMAIL] Sent successfully:", data);
  } catch (e: any) {
    console.error("[EMAIL] Send failed:", e);
    throw e;
  }
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