import { NextResponse } from "next/server";
import { createHash, createHmac } from "crypto";

export const runtime = "nodejs";

// Generate a proof token that the attestor can verify
function generateProof(email: string, userId: string): string {
  const secret = process.env.EMAIL_PROOF_SECRET || "change-me-in-production";
  const timestamp = Date.now();
  
  // HMAC(secret, email + userId + timestamp)
  const hmac = createHmac("sha256", secret)
    .update(`${email}:${userId}:${timestamp}`)
    .digest("hex");
  
  // Format: timestamp.hmac
  return `${timestamp}.${hmac}`;
}

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

  const proof = generateProof(email, id);

  return NextResponse.json({
    connected: true,
    id,
    email,
    proof,
  });
}