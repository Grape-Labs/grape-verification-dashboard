import { NextRequest, NextResponse } from "next/server";

export function proxy(request: NextRequest) {
  const pathMatch = request.nextUrl.pathname.match(/^\/dao\/([^/]+)\/?$/);
  if (!pathMatch?.[1]) return NextResponse.next();

  const rawDaoId = pathMatch[1];
  let daoId = rawDaoId;
  try {
    daoId = decodeURIComponent(rawDaoId);
  } catch {
    daoId = rawDaoId;
  }
  daoId = daoId.trim();
  if (!daoId) return NextResponse.next();

  const rewriteUrl = request.nextUrl.clone();
  rewriteUrl.pathname = "/";
  rewriteUrl.searchParams.set("dao_id", daoId);
  return NextResponse.rewrite(rewriteUrl);
}

export const config = {
  matcher: ["/dao/:path*"],
};

