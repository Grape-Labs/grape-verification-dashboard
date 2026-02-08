import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  const sessionCookie = req.cookies.get("telegram_session");

  if (!sessionCookie) {
    return NextResponse.json({ connected: false });
  }

  try {
    const session = JSON.parse(sessionCookie.value);
    return NextResponse.json({
      connected: true,
      id: session.id,
      label: session.username
        ? `@${session.username}`
        : `${session.firstName}${session.lastName ? " " + session.lastName : ""}`,
      firstName: session.firstName,
      lastName: session.lastName,
      username: session.username,
      photoUrl: session.photoUrl,
    });
  } catch {
    return NextResponse.json({ connected: false });
  }
}