import { NextResponse } from "next/server";
export const runtime = "nodejs";

function parseCookies(cookieHeader: string) {
  return Object.fromEntries(
    cookieHeader
      .split(";")
      .map((p) => p.trim())
      .filter(Boolean)
      .map((kv) => {
        const i = kv.indexOf("=");
        return [kv.slice(0, i), decodeURIComponent(kv.slice(i + 1))];
      })
  );
}

export async function GET(req: Request) {
  const cookies = parseCookies(req.headers.get("cookie") || "");
  const id = cookies["gv_discord_id"] || "";
  const label = cookies["gv_discord_label"] || "";

  return NextResponse.json({
    connected: !!id,
    id: id || null,
    label: label || null,
  });
}