import { NextResponse } from "next/server";

export const runtime = "nodejs";

function getOrigin(req: Request) {
  return new URL(req.url).origin;
}

export async function POST(req: Request) {
  const origin = getOrigin(req);
  const isHttps = origin.startsWith("https://");

  const res = NextResponse.json({ ok: true });

  res.cookies.set("gv_email_id", "", {
    path: "/",
    maxAge: 0,
  });

  res.cookies.set("gv_email_address", "", {
    path: "/",
    maxAge: 0,
  });

  res.cookies.set("gv_email_token", "", {
    path: "/",
    maxAge: 0,
  });

  return res;
}