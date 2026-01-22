import { NextResponse } from "next/server";

export const runtime = "nodejs";

function normalizeBase(raw: string) {
  const s = (raw || "").trim().replace(/\/+$/, "");
  // If someone entered "domain.com" without scheme, fix it
  if (s && !/^https?:\/\//i.test(s)) return `https://${s}`;
  return s;
}

export async function POST(req: Request) {
  const rawBase =
    process.env.ATTESTOR_API_BASE || process.env.NEXT_PUBLIC_ATTESTOR_API_BASE;

  if (!rawBase) {
    return NextResponse.json({ error: "ATTESTOR_API_BASE missing" }, { status: 500 });
  }

  const base = normalizeBase(rawBase);

  let url: string;
  try {
    // Validate it is a real absolute URL
    url = new URL(`${base}/link`).toString();
  } catch {
    return NextResponse.json(
      { error: `ATTESTOR_API_BASE is not a valid URL`, base },
      { status: 500 }
    );
  }

  const body = await req.text();

  try {
    // Helpful: small timeout so it doesn’t hang forever
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 12_000);

    const r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      signal: controller.signal,
    });

    clearTimeout(t);

    const text = await r.text().catch(() => "");
    return new NextResponse(text || "", {
      status: r.status,
      headers: { "content-type": r.headers.get("content-type") || "text/plain" },
    });
  } catch (e: any) {
    return NextResponse.json(
      {
        error: `Proxy fetch failed: ${String(e?.message || e)}`,
        target: url,
        base,
      },
      { status: 502 }
    );
  }
}