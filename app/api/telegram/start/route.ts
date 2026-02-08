import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  const botUsername = process.env.TELEGRAM_BOT_USERNAME;
  const returnTo = req.nextUrl.searchParams.get("returnTo") || "/";

  if (!botUsername) {
    return NextResponse.json(
      { error: "TELEGRAM_BOT_USERNAME not configured" },
      { status: 500 }
    );
  }

  // Store returnTo in session/cookie for callback
  const response = NextResponse.redirect(new URL(returnTo, req.url));
  response.cookies.set("telegram_return_to", returnTo, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 600, // 10 minutes
  });

  return response;
}