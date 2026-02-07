import { NextResponse } from "next/server";

export const runtime = "nodejs";

export async function GET(req: Request) {
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

  const id = cookies["gv_email_id"];
  const email = cookies["gv_email_address"];

  if (!id || !email) {
    return NextResponse.json({ connected: false });
  }

  return NextResponse.json({
    connected: true,
    id,
    email,
    label: email,
  });
}