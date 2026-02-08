import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  const response = NextResponse.json({ success: true });

  response.cookies.delete("telegram_session");
  response.cookies.delete("telegram_return_to");

  return response;
}