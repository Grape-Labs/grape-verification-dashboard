import { NextResponse } from "next/server";

export const runtime = "nodejs";

export async function POST(req: Request) {
  const base =
    process.env.ATTESTOR_API_BASE || process.env.NEXT_PUBLIC_ATTESTOR_API_BASE;

  if (!base) {
    return NextResponse.json(
      { error: "ATTESTOR_API_BASE missing" },
      { status: 500 }
    );
  }

  const body = await req.text(); // keep exact payload
  const url = `${base.replace(/\/+$/, "")}/link`;

  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });

    const text = await r.text().catch(() => "");

    return new NextResponse(text || "", {
      status: r.status,
      headers: { "content-type": r.headers.get("content-type") || "text/plain" },
    });
  } catch (e: any) {
    return NextResponse.json(
      { error: `Proxy fetch failed: ${String(e?.message || e)}` },
      { status: 502 }
    );
  }
}