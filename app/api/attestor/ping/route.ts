import { NextResponse } from "next/server";

export const runtime = "nodejs";

function normalizeBase(raw: string) {
  const s = (raw || "").trim().replace(/\/+$/, "");
  if (s && !/^https?:\/\//i.test(s)) return `https://${s}`;
  return s;
}

export async function GET() {
  const rawBase =
    process.env.ATTESTOR_API_BASE || process.env.NEXT_PUBLIC_ATTESTOR_API_BASE;

  if (!rawBase) {
    return NextResponse.json({ ok: false, error: "ATTESTOR_API_BASE missing" }, { status: 500 });
  }

  const base = normalizeBase(rawBase);
  let url: string;

  try {
    url = new URL(base).toString();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid base URL", base }, { status: 500 });
  }

  try {
    const r = await fetch(url, { method: "GET" });
    const text = await r.text().catch(() => "");
    return NextResponse.json({ ok: true, status: r.status, base: url, sample: text.slice(0, 120) });
  } catch (e: any) {
    return NextResponse.json(
      { ok: false, error: String(e?.message || e), base: url },
      { status: 502 }
    );
  }
}