// In-memory store for verification codes (use Redis/DB in production)
export const verificationCodes = new Map<
  string,
  { code: string; email: string; expiresAt: number }
>();

// Clean up expired codes every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of verificationCodes.entries()) {
    if (now > data.expiresAt) {
      verificationCodes.delete(token);
    }
  }
}, 5 * 60 * 1000);