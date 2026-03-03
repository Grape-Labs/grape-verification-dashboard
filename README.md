# Grape Verification Dashboard

Dashboard for Grape Verification communities on Solana.

It lets users connect identity platforms (Discord, Telegram, Email), generate platform proofs, and link or unlink wallets on-chain through the attestor API.

## Product Links
- Documentation: https://grapedao.gitbook.io/products/grape-verification
- Discord: https://discord.gg/xrxrCmvB
- GitHub: https://github.com/Grape-Labs/grape-verification-dashboard

## Stack
- Next.js 16 (App Router)
- React 19
- MUI 7
- Solana wallet adapter + `@solana/web3.js`
- `@grapenpm/grape-verification-registry`

## Prerequisites
- Node.js 20+
- npm or yarn
- A Solana wallet for signing link/unlink/admin messages
- Discord OAuth app (for Discord flow)
- Telegram bot token (for Telegram flow)
- Resend API key (for email flow)

## Local Setup
1. Install dependencies:

```bash
npm install
```

2. Create `.env.local` with the variables you need (see below).

3. Start development server:

```bash
npm run dev
```

4. Open http://localhost:3000

## Environment Variables

### Core
- `NEXT_PUBLIC_SOLANA_RPC`: Solana RPC URL used by UI and attestor routes.
- `REACT_APP_RPC_ENDPOINT`: Fallback RPC URL used by some API routes.
- `NEXT_PUBLIC_APP_URL`: Public app URL (for OAuth and redirects).
- `APP_URL`: Optional server-side override for app URL.
- `NEXT_PUBLIC_DEFAULT_DAO_ID`: Optional default DAO loaded by the UI.
- `NEXT_PUBLIC_COMMUNITIES` or `NEXT_PUBLIC_COMMUNITY_REGISTRY`: Optional community registry JSON.
- `NEXT_PUBLIC_DISCORD_GUILD_DAO_MAP`: Optional JSON map of Discord guild id to DAO id.
- `NEXT_PUBLIC_ATTESTOR_PUBKEY`: Optional UI display hint for attestor pubkey.
- `NEXT_PUBLIC_TELEGRAM_BOT_USERNAME`: Optional UI display value.
- `NEXT_PUBLIC_ATTESTOR_API_BASE` or `ATTESTOR_API_BASE`: Optional base URL used by `/api/attestor/ping`.

### Discord
- `DISCORD_CLIENT_ID`: Discord OAuth client id.
- `DISCORD_CLIENT_SECRET`: Discord OAuth client secret.
- `DISCORD_PROOF_SECRET`: HMAC secret used for Discord proof minting/verification.

### Telegram
- `TELEGRAM_BOT_USERNAME`: Telegram bot username.
- `TELEGRAM_BOT_TOKEN`: Telegram bot token (used to verify Telegram login payload).
- `TELEGRAM_PROOF_SECRET`: HMAC secret used for Telegram proof minting/verification.

### Email
- `RESEND_API_KEY`: API key for sending email verification codes.
- `EMAIL_PROOF_SECRET`: HMAC secret used for email proof minting/verification.

### Attestor Keys
- `ATTESTOR_SECRET_KEYS_BY_DAO`: Optional per-DAO map of signing keys (preferred).
- `ATTESTOR_SECRET_KEY`: Fallback signing key when no DAO-specific key is found.
- `KV_REST_API_URL`: Optional Upstash/Vercel KV REST URL for per-DAO key storage.
- `KV_REST_API_TOKEN`: Optional KV token.

Accepted key format for attestor keys is JSON byte array (`[1,2,...]`) or base64/base64url.

Example `ATTESTOR_SECRET_KEYS_BY_DAO`:

```json
{
  "<daoPubkey>": { "secretKey": "<base64-or-json-array-string>" },
  "default": "<base64-or-json-array-string>"
}
```

## Discord OAuth Configuration
Configure your Discord application redirect URI to include:
- `http://localhost:3000/api/discord/callback` (local)
- `https://<your-domain>/api/discord/callback` (production)

## Scripts
```bash
npm run dev    # local development
npm run build  # production build
npm run start  # run production server
npm run lint   # eslint
```

## Operational Notes
- Email verification codes are currently kept in-memory in the app process. Restarting the server clears active codes.
- Do not commit `.env.local` or private keys.
- The dashboard includes both client UI and server API routes under `app/api/*`.
