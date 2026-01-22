import { NextResponse } from "next/server";

export const runtime = "nodejs";

function getOrigin(req: Request) {
  return new URL(req.url).origin;
}

async function exchangeCodeForToken(code: string, redirectUri: string) {
  const clientId = process.env.DISCORD_CLIENT_ID!;
  const clientSecret = process.env.DISCORD_CLIENT_SECRET!;

  const body = new URLSearchParams();
  body.set("client_id", clientId);
  body.set("client_secret", clientSecret);
  body.set("grant_type", "authorization_code");
  body.set("code", code);
  body.set("redirect_uri", redirectUri);

  const resp = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!resp.ok) {
    const t = await resp.text().catch(() => "");
    throw new Error(
      `Token exchange failed (${resp.status}): ${t || resp.statusText}`
    );
  }

  return resp.json() as Promise<{
    access_token: string;
    token_type: string;
    expires_in: number;
  }>;
}

async function fetchDiscordMe(accessToken: string) {
  const resp = await fetch("https://discord.com/api/users/@me", {
    headers: { authorization: `Bearer ${accessToken}` },
  });

  if (!resp.ok) {
    const t = await resp.text().catch(() => "");
    throw new Error(
      `Fetch /users/@me failed (${resp.status}): ${t || resp.statusText}`
    );
  }

  return resp.json() as Promise<{
    id: string;
    username: string;
    global_name?: string;
    avatar?: string;
  }>;
}

export async function GET(req: Request) {
  const reqUrl = new URL(req.url);
  const origin = getOrigin(req);

  const clientId = process.env.DISCORD_CLIENT_ID;
  const clientSecret = process.env.DISCORD_CLIENT_SECRET;

  if (!clientId)
    return NextResponse.json(
      { error: "DISCORD_CLIENT_ID missing" },
      { status: 500 }
    );
  if (!clientSecret)
    return NextResponse.json(
      { error: "DISCORD_CLIENT_SECRET missing" },
      { status: 500 }
    );

  const code = reqUrl.searchParams.get("code");
  const state = reqUrl.searchParams.get("state");

  if (!code || !state)
    return NextResponse.json(
      { error: "Missing code/state" },
      { status: 400 }
    );

  // Parse cookies
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

  const expectedState = cookies["gv_discord_oauth_state"];
  const returnTo = cookies["gv_discord_return_to"] || "/";

  if (!expectedState || expectedState !== state) {
    return NextResponse.json({ error: "Invalid state" }, { status: 400 });
  }

  // 🔒 Ensure same redirect_uri used in /start
  const redirectUri = `${origin}/api/discord/callback`;

  try {
    const tok = await exchangeCodeForToken(code, redirectUri);
    const me = await fetchDiscordMe(tok.access_token);

    const isHttps = origin.startsWith("https://");

    // Prevent open redirects
    const safeReturnTo =
      returnTo.startsWith("/") && !returnTo.startsWith("//")
        ? returnTo
        : "/";

    const res = NextResponse.redirect(
      new URL(safeReturnTo, origin).toString()
    );

    // Clear OAuth temp cookies
    res.cookies.set("gv_discord_oauth_state", "", {
      path: "/",
      maxAge: 0,
    });
    res.cookies.set("gv_discord_return_to", "", {
      path: "/",
      maxAge: 0,
    });

    // Store Discord ID (httpOnly)
    res.cookies.set("gv_discord_id", me.id, {
      httpOnly: true,
      secure: isHttps,
      sameSite: "lax",
      path: "/",
      maxAge: 7 * 24 * 60 * 60,
    });

    // UI-friendly label (non-httpOnly)
    res.cookies.set(
      "gv_discord_label",
      me.global_name || me.username || "Discord",
      {
        httpOnly: false,
        secure: isHttps,
        sameSite: "lax",
        path: "/",
        maxAge: 7 * 24 * 60 * 60,
      }
    );

    return res;
  } catch (e: any) {
    return NextResponse.json(
      { error: String(e?.message || e) },
      { status: 500 }
    );
  }
}