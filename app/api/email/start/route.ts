import { NextResponse } from "next/server";
import { randomBytes } from "crypto";

export const runtime = "nodejs";

function getOrigin(req: Request) {
  return new URL(req.url).origin;
}

export async function GET(req: Request) {
  const reqUrl = new URL(req.url);
  const origin = getOrigin(req);

  const returnTo = reqUrl.searchParams.get("returnTo") || "/";

  // Generate a session token for email verification
  const token = randomBytes(32).toString("hex");

  const isHttps = origin.startsWith("https://");

  // ✅ Return JSON instead of redirect so we can verify cookie was set
  const res = NextResponse.json({ ok: true, token });

  // Store session token (for tracking verification flow)
  res.cookies.set("gv_email_token", token, {
    httpOnly: true,
    secure: isHttps,
    sameSite: "lax",
    path: "/",
    maxAge: 15 * 60, // 15 minutes
  });

  res.cookies.set("gv_email_return_to", returnTo, {
    httpOnly: true,
    secure: isHttps,
    sameSite: "lax",
    path: "/",
    maxAge: 15 * 60,
  });

  return res;
}