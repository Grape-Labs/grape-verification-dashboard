import { NextResponse } from "next/server";

export const runtime = "nodejs";

function base64url(input: Uint8Array) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function randomState() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

function getOrigin(req: Request) {
  const fromEnv = (process.env.APP_URL || process.env.NEXT_PUBLIC_APP_URL || "").trim();

  if (fromEnv) {
    // Auto-fix missing scheme
    if (!/^https?:\/\//i.test(fromEnv)) {
      return `https://${fromEnv.replace(/\/+$/, "")}`;
    }
    return fromEnv.replace(/\/+$/, "");
  }

  // ✅ Always correct on Vercel
  return new URL(req.url).origin;
}

export async function GET(req: Request) {
  const url = new URL(req.url);

  const clientId = process.env.DISCORD_CLIENT_ID;
  if (!clientId) {
    return NextResponse.json({ error: "DISCORD_CLIENT_ID missing" }, { status: 500 });
  }

  const origin = getOrigin(req);
  const redirectUri = `${origin}/api/discord/callback`;

  const returnTo = url.searchParams.get("returnTo") || "/";
  const state = randomState();

  const auth = new URL("https://discord.com/api/oauth2/authorize");
  auth.searchParams.set("client_id", clientId);
  auth.searchParams.set("redirect_uri", redirectUri);
  auth.searchParams.set("response_type", "code");
  auth.searchParams.set("scope", "identify");
  auth.searchParams.set("state", state);

  const res = NextResponse.redirect(auth.toString());
  const isHttps = origin.startsWith("https://");

  res.cookies.set("gv_discord_oauth_state", state, {
    httpOnly: true,
    secure: isHttps,
    sameSite: "lax",
    path: "/",
    maxAge: 10 * 60,
  });

  res.cookies.set("gv_discord_return_to", returnTo, {
    httpOnly: true,
    secure: isHttps,
    sameSite: "lax",
    path: "/",
    maxAge: 10 * 60,
  });

  return res;
}