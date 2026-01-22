import { NextResponse } from "next/server";
export const runtime = "nodejs";

export async function POST() {
  const appUrl = process.env.NEXT_PUBLIC_APP_URL || "";
  const isHttps = appUrl.startsWith("https://");

  const res = NextResponse.json({ ok: true });
  res.cookies.set("gv_discord_id", "", { path: "/", maxAge: 0, httpOnly: true, secure: isHttps, sameSite: "lax" });
  res.cookies.set("gv_discord_label", "", { path: "/", maxAge: 0, httpOnly: false, secure: isHttps, sameSite: "lax" });
  return res;
}