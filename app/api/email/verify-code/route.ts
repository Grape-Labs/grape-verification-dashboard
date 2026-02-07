import { NextResponse } from "next/server";
import { createHash } from "crypto";

export const runtime = "nodejs";

// ✅ Access the same global Map
declare global {
  var emailVerificationCodes: Map<
    string,
    { code: string; email: string; expiresAt: number }
  > | undefined;
}

function getOrigin(req: Request) {
  return new URL(req.url).origin;
}

// Create a deterministic user ID from email (hash)
function emailToUserId(email: string): string {
  return createHash("sha256").update(email.toLowerCase()).digest("hex").slice(0, 16);
}

export async function POST(req: Request) {
  const origin = getOrigin(req);

  try {
    const body = await req.json();
    const code = body.code?.trim();

    if (!code) {
      return NextResponse.json({ error: "Code required" }, { status: 400 });
    }

    // Parse cookies
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
      return NextResponse.json({ error: "No session token" }, { status: 400 });
    }

    // ✅ Check code from global Map
    if (!global.emailVerificationCodes) {
      return NextResponse.json(
        { error: "Verification system not initialized" },
        { status: 500 }
      );
    }

    const data = global.emailVerificationCodes.get(token);
    if (!data) {
      return NextResponse.json(
        { error: "No verification pending or code expired" },
        { status: 400 }
      );
    }

    if (Date.now() > data.expiresAt) {
      global.emailVerificationCodes.delete(token);
      return NextResponse.json(
        { error: "Code expired. Please request a new one." },
        { status: 400 }
      );
    }

    if (data.code !== code) {
      return NextResponse.json(
        { error: "Invalid code. Please try again." },
        { status: 400 }
      );
    }

    // Code is valid!
    global.emailVerificationCodes.delete(token);

    const userId = emailToUserId(data.email);
    const isHttps = origin.startsWith("https://");

    const res = NextResponse.json({ ok: true, email: data.email, userId });

    // Clear temp token
    res.cookies.set("gv_email_token", "", {
      path: "/",
      maxAge: 0,
    });

    res.cookies.set("gv_email_return_to", "", {
      path: "/",
      maxAge: 0,
    });

    // Store verified email ID (httpOnly)
    res.cookies.set("gv_email_id", userId, {
      httpOnly: true,
      secure: isHttps,
      sameSite: "lax",
      path: "/",
      maxAge: 7 * 24 * 60 * 60,
    });

    // Store email address for UI (non-httpOnly)
    res.cookies.set("gv_email_address", data.email, {
      httpOnly: false,
      secure: isHttps,
      sameSite: "lax",
      path: "/",
      maxAge: 7 * 24 * 60 * 60,
    });

    return res;
  } catch (e: any) {
    console.error("[EMAIL] Verify error:", e);
    return NextResponse.json(
      { error: String(e?.message || e) },
      { status: 500 }
    );
  }
}