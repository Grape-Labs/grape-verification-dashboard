"use client";

import React, { useEffect, useMemo, useState } from "react";
import {
  Box,
  Button,
  Chip,
  Container,
  Divider,
  Paper,
  Stack,
  Typography,
} from "@mui/material";

import BoltIcon from "@mui/icons-material/Bolt";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import LinkIcon from "@mui/icons-material/Link";
import TravelExploreIcon from "@mui/icons-material/TravelExplore";
import TuneIcon from "@mui/icons-material/Tune";
import VerifiedIcon from "@mui/icons-material/Verified";

import { useConnection, useWallet } from "@solana/wallet-adapter-react";
import { Connection, PublicKey } from "@solana/web3.js";

import CreateSpaceDialog from "./components/CreateSpaceDialog";
import WalletComicButton from "./components/WalletComicButton";

// ✅ Your published client helpers
import {
  VerificationPlatform,
  deriveIdentityPda,
  deriveLinkPda,
  deriveSpacePda,
  identityHash,
  walletHash,
  TAG_DISCORD,
  TAG_EMAIL,
  TAG_TELEGRAM,
  TAG_TWITTER,
} from "@grapenpm/grape-verification-registry";

type PlatformKey = "discord" | "telegram" | "twitter" | "email";

function platformSeed(platform: PlatformKey): number {
  switch (platform) {
    case "discord":
      return VerificationPlatform.Discord;
    case "telegram":
      return VerificationPlatform.Telegram;
    case "twitter":
      return VerificationPlatform.Twitter;
    case "email":
      return VerificationPlatform.Email;
    default:
      return VerificationPlatform.Discord;
  }
}

function platformTag(platform: PlatformKey): string {
  switch (platform) {
    case "discord":
      return TAG_DISCORD;
    case "telegram":
      return TAG_TELEGRAM;
    case "twitter":
      return TAG_TWITTER;
    case "email":
      return TAG_EMAIL;
    default:
      return TAG_DISCORD;
  }
}

function shortB58(pk: PublicKey | null | undefined) {
  if (!pk) return "—";
  const s = pk.toBase58();
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

function b58(pk: PublicKey | null | undefined) {
  return pk ? pk.toBase58() : "—";
}

function bytesToHex(u8: Uint8Array | null) {
  if (!u8) return "—";
  return Array.from(u8)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Space.salt layout:
 * discriminator(8)
 * version(1)
 * dao_id(32)
 * authority(32)
 * attestor(32)
 * is_frozen(1)
 * bump(1)
 * salt(32)
 */
function parseSpaceSalt(data: Uint8Array): Uint8Array {
  const SALT_OFFSET = 8 + 1 + 32 + 32 + 32 + 1 + 1; // 107
  return data.slice(SALT_OFFSET, SALT_OFFSET + 32);
}

/**
 * Identity layout:
 * disc(8)
 * version u8
 * space Pubkey (32)
 * platform u8
 * id_hash [32]
 * verified bool(u8)
 * verified_at i64
 * expires_at i64
 * attested_by Pubkey (32)
 * bump u8
 * padding [4]
 */
function parseIdentity(data: Uint8Array) {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let o = 8;

  const version = dv.getUint8(o);
  o += 1;

  const space = new PublicKey(data.slice(o, o + 32));
  o += 32;

  const platform = dv.getUint8(o);
  o += 1;

  const idHash = data.slice(o, o + 32);
  o += 32;

  const verified = dv.getUint8(o) === 1;
  o += 1;

  const verifiedAt = Number(dv.getBigInt64(o, true));
  o += 8;

  const expiresAt = Number(dv.getBigInt64(o, true));
  o += 8;

  const attestedBy = new PublicKey(data.slice(o, o + 32));
  o += 32;

  const bump = dv.getUint8(o);

  return {
    version,
    space,
    platform,
    idHash,
    verified,
    verifiedAt,
    expiresAt,
    attestedBy,
    bump,
  };
}

/**
 * Link layout:
 * disc(8)
 * version u8
 * identity Pubkey (32)
 * wallet_hash [32]
 * linked_at i64
 * bump u8
 * padding [6]
 */
function parseLink(data: Uint8Array) {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let o = 8;

  const version = dv.getUint8(o);
  o += 1;

  const identity = new PublicKey(data.slice(o, o + 32));
  o += 32;

  const walletHashBytes = data.slice(o, o + 32);
  o += 32;

  const linkedAt = Number(dv.getBigInt64(o, true));
  o += 8;

  const bump = dv.getUint8(o);

  return { version, identity, walletHashBytes, linkedAt, bump };
}

function fmtTs(ts: number) {
  if (!ts) return "—";
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch {
    return String(ts);
  }
}

async function safeGetAccountInfo(connection: Connection, pubkey: PublicKey) {
  try {
    return await connection.getAccountInfo(pubkey);
  } catch {
    return null;
  }
}

function modeFromLocalStorage(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.localStorage.getItem("gv_mode") === "advanced";
  } catch {
    return false;
  }
}

function setModeToLocalStorage(advanced: boolean) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem("gv_mode", advanced ? "advanced" : "simple");
  } catch {
    // ignore
  }
}

export default function Page() {
  const { connection } = useConnection();
  const { publicKey, signMessage } = useWallet();

  // -------------------------------
  // Mode: SIMPLE (default) vs ADVANCED
  // -------------------------------
  const [advancedMode, setAdvancedMode] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);

  const [discordConnected, setDiscordConnected] = useState(false);
  const [discordLabel, setDiscordLabel] = useState<string | null>(null);
  const [discordProof, setDiscordProof] = useState<string | null>(null);

  useEffect(() => {
    const adv = modeFromLocalStorage();
    setAdvancedMode(adv);
    setAdvancedOpen(adv);
  }, []);

  const toggleMode = () => {
    setAdvancedMode((v) => {
      const next = !v;
      setModeToLocalStorage(next);
      setAdvancedOpen(next);
      return next;
    });
  };

  // -------------------------------
  // Existing state
  // -------------------------------
  const [daoIdStr, setDaoIdStr] = useState(
    process.env.NEXT_PUBLIC_DEFAULT_DAO_ID || ""
  );
  const [platform, setPlatform] = useState<PlatformKey>("discord");
  const [platformUserId, setPlatformUserId] = useState("");

  const [spacePda, setSpacePda] = useState<PublicKey | null>(null);
  const [spaceSalt, setSpaceSalt] = useState<Uint8Array | null>(null);
  const [spaceExists, setSpaceExists] = useState<boolean | null>(null);
  const [spaceFrozen, setSpaceFrozen] = useState<boolean | null>(null);

  const [idHashBytes, setIdHashBytes] = useState<Uint8Array | null>(null);
  const [identityPda, setIdentityPda] = useState<PublicKey | null>(null);
  const [identityExists, setIdentityExists] = useState<boolean | null>(null);
  const [identityInfo, setIdentityInfo] = useState<
    ReturnType<typeof parseIdentity> | null
  >(null);

  const [walletHashBytes, setWalletHashBytes] = useState<Uint8Array | null>(
    null
  );
  const [linkPda, setLinkPda] = useState<PublicKey | null>(null);
  const [linkExists, setLinkExists] = useState<boolean | null>(null);
  const [linkInfo, setLinkInfo] = useState<ReturnType<typeof parseLink> | null>(
    null
  );

  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");

  const [spaceDialogOpen, setSpaceDialogOpen] = useState(false);

  const daoPk = useMemo(() => {
    try {
      const s = daoIdStr.trim();
      if (!s) return null;
      return new PublicKey(s);
    } catch {
      return null;
    }
  }, [daoIdStr]);

  // --- Load Space PDA + account ---
  useEffect(() => {
    let cancelled = false;

    async function run() {
      setError("");
      setMsg("");

      setSpacePda(null);
      setSpaceSalt(null);
      setSpaceExists(null);
      setSpaceFrozen(null);

      setIdentityPda(null);
      setIdentityExists(null);
      setIdentityInfo(null);

      setLinkPda(null);
      setLinkExists(null);
      setLinkInfo(null);

      if (!daoPk) return;

      const [pda] = deriveSpacePda(daoPk);
      setSpacePda(pda);

      const acct = await safeGetAccountInfo(connection, pda);
      if (cancelled) return;

      setSpaceExists(!!acct);
      if (!acct) return;

      const salt = parseSpaceSalt(acct.data);
      setSpaceSalt(salt);

      const FROZEN_OFFSET = 8 + 1 + 32 + 32 + 32; // 105
      setSpaceFrozen(acct.data[FROZEN_OFFSET] === 1);
    }

    run().catch((e) => setError(String(e?.message || e)));
    return () => {
      cancelled = true;
    };
  }, [connection, daoPk]);

  // --- Derive Identity + Link and load accounts ---
  useEffect(() => {
    let cancelled = false;

    async function run() {
      setError("");
      setMsg("");

      setIdHashBytes(null);
      setIdentityPda(null);
      setIdentityExists(null);
      setIdentityInfo(null);

      setWalletHashBytes(null);
      setLinkPda(null);
      setLinkExists(null);
      setLinkInfo(null);

      if (!spacePda || !spaceSalt) return;
      if (!platformUserId.trim()) return;

      const idh = identityHash(
        spaceSalt,
        platformTag(platform),
        platformUserId.trim()
      );
      setIdHashBytes(idh);

      const [idPda] = deriveIdentityPda(spacePda, platformSeed(platform), idh);
      setIdentityPda(idPda);

      const idAcct = await safeGetAccountInfo(connection, idPda);
      if (cancelled) return;

      setIdentityExists(!!idAcct);
      setIdentityInfo(idAcct ? parseIdentity(idAcct.data) : null);

      if (!publicKey) return;

      const wh = walletHash(spaceSalt, publicKey);
      setWalletHashBytes(wh);

      const [lPda] = deriveLinkPda(idPda, wh);
      setLinkPda(lPda);

      const lAcct = await safeGetAccountInfo(connection, lPda);
      if (cancelled) return;

      setLinkExists(!!lAcct);
      setLinkInfo(lAcct ? parseLink(lAcct.data) : null);
    }

    run().catch((e) => setError(String(e?.message || e)));
    return () => {
      cancelled = true;
    };
  }, [connection, spacePda, spaceSalt, platform, platformUserId, publicKey]);


  async function loadDiscordSession() {
    try {
      const me = await fetch("/api/discord/me", { cache: "no-store" }).then((r) => r.json());
      setDiscordConnected(!!me?.connected);
      setDiscordLabel(me?.label || null);

      if (me?.connected && me?.id && platform === "discord") {
        // ✅ Auto-fill platformUserId for Discord
        setPlatformUserId(String(me.id));
      }
    } catch {
      setDiscordConnected(false);
      setDiscordLabel(null);
    }
  }

  async function loadDiscordProof() {
    try {
      const r = await fetch("/api/discord/proof", { cache: "no-store" });
      const j = await r.json();
      if (j?.connected && j?.proof) setDiscordProof(j.proof);
      else setDiscordProof(null);
    } catch {
      setDiscordProof(null);
    }
  }

  function startDiscordConnect() {
    const returnTo =
      typeof window !== "undefined" ? window.location.pathname + window.location.search : "/";
    window.location.href = `/api/discord/start?returnTo=${encodeURIComponent(returnTo)}`;
  }

  async function disconnectDiscord() {
    await fetch("/api/discord/disconnect", { method: "POST" }).catch(() => {});
    setDiscordConnected(false);
    setDiscordLabel(null);
    setDiscordProof(null);
    if (platform === "discord") setPlatformUserId("");
  }

  useEffect(() => {
    if (platform !== "discord") return;
    loadDiscordSession();
    loadDiscordProof();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [platform]);

  const identityStatus = useMemo(() => {
    if (identityExists === false) return "Not found";
    if (!identityInfo) return identityExists ? "Unknown" : "—";

    const now = Math.floor(Date.now() / 1000);
    const expired = identityInfo.expiresAt > 0 && now > identityInfo.expiresAt;

    if (!identityInfo.verified) return "Revoked / not verified";
    if (expired) return "Verified (expired)";
    return "Verified";
  }, [identityExists, identityInfo]);

  async function refresh() {
    // triggers effects without hacks
    setDaoIdStr((v) => v);
    setPlatformUserId((v) => v);
  }

  async function signLinkRequest() {
    setError("");
    setMsg("");

    if (!signMessage) {
      setError("Wallet does not support signMessage (try Phantom/Solflare).");
      return;
    }
    if (!daoPk || !spacePda || !spaceSalt) {
      setError("Missing DAO/space. Ensure the Space account exists on-chain.");
      return;
    }
    if (!publicKey) {
      setError("Connect a wallet first.");
      return;
    }
    if (!platformUserId.trim()) {
      setError("Enter a platform user id (temporary for MVP).");
      return;
    }

    // Ensure hashes exist (effects should set them, but this keeps UX resilient)
    const idh =
      idHashBytes ??
      identityHash(spaceSalt, platformTag(platform), platformUserId.trim());

    const wh = walletHashBytes ?? walletHash(spaceSalt, publicKey);

    if (!idHashBytes) setIdHashBytes(idh);
    if (!walletHashBytes) setWalletHashBytes(wh);

    const payload = {
      daoId: daoPk.toBase58(),
      space: spacePda.toBase58(),
      platform,
      platformSeed: platformSeed(platform),
      idHashHex: bytesToHex(idh),
      wallet: publicKey.toBase58(),
      walletHashHex: bytesToHex(wh),
      ts: Date.now(),
    };

    const message = new TextEncoder().encode(
      `Grape Verification Link Request\n` +
        `daoId=${payload.daoId}\n` +
        `space=${payload.space}\n` +
        `platform=${payload.platform}\n` +
        `idHash=${payload.idHashHex}\n` +
        `wallet=${payload.wallet}\n` +
        `walletHash=${payload.walletHashHex}\n` +
        `ts=${payload.ts}\n`
    );

    const sig = await signMessage(message);
    const sigB64 = btoa(String.fromCharCode(...sig));

    setMsg(
      `✅ Signed consent message.\n\n` +
        `Payload (send to attestor):\n${JSON.stringify(payload, null, 2)}\n\n` +
        `Signature (base64):\n${sigB64}`
    );
  }

  async function postToAttestor() {
    setError("");
    setMsg("");

    const base = process.env.NEXT_PUBLIC_ATTESTOR_API_BASE;
    if (!base) {
      setError("NEXT_PUBLIC_ATTESTOR_API_BASE is not set.");
      return;
    }

    if (!signMessage) {
      setError("Wallet does not support signMessage.");
      return;
    }
    if (!daoPk || !spacePda || !spaceSalt || !publicKey) {
      setError("Missing DAO/space/wallet. Ensure Space exists and wallet connected.");
      return;
    }
    if (!platformUserId.trim()) {
      setError("Enter a platform user id (temporary for MVP).");
      return;
    }

    const idh =
      idHashBytes ??
      identityHash(spaceSalt, platformTag(platform), platformUserId.trim());
    const wh = walletHashBytes ?? walletHash(spaceSalt, publicKey);

    if (!idHashBytes) setIdHashBytes(idh);
    if (!walletHashBytes) setWalletHashBytes(wh);

    const platformProofValue =
      platform === "discord" ? (discordProof || null) : null;

    const payload = {
      daoId: daoPk.toBase58(),
      platform,
      platformSeed: platformSeed(platform),
      platformUserId: platformUserId.trim(),
      platformProof: platformProofValue,
      idHashHex: bytesToHex(idh),
      wallet: publicKey.toBase58(),
      walletHashHex: bytesToHex(wh),
      ts: Date.now(),
      space: spacePda.toBase58(),
    };

    const message = new TextEncoder().encode(
      `Grape Verification Link Request\n` +
        `daoId=${payload.daoId}\n` +
        `platform=${payload.platform}\n` +
        `idHash=${payload.idHashHex}\n` +
        `wallet=${payload.wallet}\n` +
        `walletHash=${payload.walletHashHex}\n` +
        `ts=${payload.ts}\n`
    );

    const sig = await signMessage(message);
    const sigB64 = btoa(String.fromCharCode(...sig));

    const res = await fetch(`/api/attestor/link`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ payload, signatureBase64: sigB64 }),
    });

    if (!res.ok) {
      const t = await res.text().catch(() => "");
      throw new Error(`Attestor error (${res.status}): ${t || res.statusText}`);
    }

    setMsg(`✅ Submitted to attestor.\n\nResponse:\n${await res.text()}`);
    await refresh();
  }

  const linkChipLabel =
    linkExists == null
      ? "Link: —"
      : linkExists
      ? "Link: exists"
      : "Link: missing";

  // -------------------------------
  // SIMPLE MODE: human-friendly status
  // -------------------------------
  const simpleSteps = useMemo(() => {
    const walletOk = !!publicKey;
    const spaceOk = spaceExists === true;

    // keep your behavior: treat "Verified (expired)" as verifiedOk too
    const verifiedOk =
      identityInfo?.verified === true && identityStatus.startsWith("Verified");

    const linkOk = linkExists === true;

    return { walletOk, spaceOk, verifiedOk, linkOk };
  }, [publicKey, spaceExists, identityInfo, identityStatus, linkExists]);

  return (
    <Box
      sx={{
        py: 4,
        minHeight: "100vh",
        background:
          "radial-gradient(1200px 600px at 20% 0%, rgba(124,77,255,0.22), transparent 60%)," +
          "radial-gradient(900px 500px at 90% 10%, rgba(38,198,255,0.18), transparent 55%)," +
          "radial-gradient(circle at 1px 1px, rgba(255,255,255,0.06) 1px, rgba(0,0,0,0) 1.6px)," +
          "linear-gradient(180deg, #070A12, #050610)",
        backgroundSize: "auto, auto, 12px 12px, auto",
      }}
    >
      <Container maxWidth="lg">
        {/* Header */}
        <Paper sx={{ p: 2.5 }}>
          <Stack
            direction={{ xs: "column", sm: "row" }}
            spacing={2}
            alignItems="center"
            justifyContent="space-between"
          >
            <Stack direction="row" spacing={2} alignItems="center">
              <Box
                sx={{
                  width: 64,
                  height: 64,
                  borderRadius: "18px",
                  border: "3px solid #0b1220",
                  boxShadow: "4px 4px 0 #0b1220",
                  overflow: "hidden",
                  background: "#fff",
                }}
              >
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src="/apple-grape-touch-icon.png"
                  alt="Grape OG"
                  style={{ width: "100%", height: "100%", objectFit: "cover" }}
                />
              </Box>

              <Box>
                <Typography variant="h2" sx={{ lineHeight: 1 }}>
                  Grape Verification
                </Typography>
                <Typography
                  variant="body2"
                  sx={{ opacity: 0.75, fontFamily: "system-ui" }}
                >
                  Devnet • Privacy-preserving identity ↔ wallet linking
                </Typography>
              </Box>
            </Stack>

            <Stack direction="row" spacing={1} alignItems="center">
              <Button
                onClick={toggleMode}
                startIcon={<TuneIcon />}
                sx={{
                  borderRadius: 999,
                  px: 2,
                  fontFamily: '"Bangers", system-ui',
                  letterSpacing: 0.6,
                  background: "rgba(255,255,255,0.08)",
                  border: "2px solid rgba(255,255,255,0.14)",
                  color: "rgba(255,255,255,0.92)",
                  "&:hover": { background: "rgba(255,255,255,0.12)" },
                }}
              >
                {advancedMode ? "Advanced" : "Simple"}
              </Button>

              <Box sx={{ transform: "rotate(-1deg)" }}>
                <WalletComicButton />
              </Box>
            </Stack>
          </Stack>

          <Divider sx={{ my: 2 }} />

          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            <Chip
              icon={<BoltIcon />}
              label="Comic Mode"
              color="secondary"
              sx={{ fontFamily: "system-ui" }}
            />
            <Chip
              icon={<VerifiedIcon />}
              label={`Identity: ${identityStatus}`}
              sx={{ fontFamily: "system-ui" }}
            />
            <Chip
              icon={<LinkIcon />}
              label={linkChipLabel}
              sx={{ fontFamily: "system-ui" }}
            />
            <Chip
              icon={<TravelExploreIcon />}
              label="Token-gate Ready"
              sx={{ fontFamily: "system-ui" }}
            />
          </Stack>
        </Paper>

        {/* ===========================
            SIMPLE MODE (default)
           =========================== */}
        {!advancedMode && (
          <Paper sx={{ p: 2.5, mt: 2.5 }}>
            <Typography variant="h3" sx={{ mb: 0.5 }}>
              Verify &amp; Link
            </Typography>
            <Typography
              variant="body2"
              sx={{ opacity: 0.78, fontFamily: "system-ui" }}
            >
              Connect your wallet, verify your identity, then link. (Advanced
              details are hidden.)
            </Typography>

            <Divider sx={{ my: 2 }} />

            <Stack spacing={1.25}>
              <SimpleStep
                n={1}
                title="Connect wallet"
                ok={simpleSteps.walletOk}
                detail={
                  publicKey ? `Connected: ${shortB58(publicKey)}` : "Not connected"
                }
              />

              <SimpleStep
                n={2}
                title="Community ready"
                ok={simpleSteps.spaceOk}
                detail={
                  spaceExists === true
                    ? "Ready"
                    : spaceExists === false
                    ? "Not enabled (ask an admin)"
                    : "Checking…"
                }
              />

              <SimpleStep
                n={3}
                title="Identity verified"
                ok={simpleSteps.verifiedOk}
                detail={identityStatus === "—" ? "Enter your platform ID to check" : identityStatus}
              />

              <SimpleStep
                n={4}
                title="Wallet linked"
                ok={simpleSteps.linkOk}
                detail={
                  linkExists == null ? "—" : linkExists ? "Linked ✅" : "Not linked yet"
                }
              />

              <Divider sx={{ my: 1.5, borderColor: "rgba(255,255,255,0.10)" }} />

              {/* Minimal inputs (still MVP: platformUserId manual) */}
              <Stack spacing={1}>
                <Typography
                  sx={{ fontFamily: '"Bangers", system-ui', letterSpacing: 0.6 }}
                >
                  Platform
                </Typography>

                <Box
                  component="select"
                  value={platform}
                  onChange={(e: any) => setPlatform(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "12px 12px",
                    borderRadius: 16,
                    border: "3px solid #0b1220",
                    outline: "none",
                    fontFamily: "system-ui",
                    background: "rgba(255,255,255,0.06)",
                    color: "rgba(255,255,255,0.92)",
                  }}
                >
                  <option value="discord">Discord</option>
                  <option value="telegram">Telegram</option>
                  <option value="twitter">Twitter</option>
                  <option value="email">Email</option>
                </Box>
                
                {platform === "discord" && (
                  <Paper
                    sx={{
                      p: 1.25,
                      background: "rgba(255,255,255,0.05)",
                      border: "2px solid rgba(255,255,255,0.10)",
                      borderRadius: 3,
                    }}
                  >
                    <Stack
                      direction={{ xs: "column", sm: "row" }}
                      spacing={1}
                      alignItems={{ xs: "stretch", sm: "center" }}
                      justifyContent="space-between"
                    >
                      <Box>
                        <Typography sx={{ fontFamily: '"Bangers", system-ui', letterSpacing: 0.6 }}>
                          Discord
                        </Typography>
                        <Typography sx={{ fontFamily: "system-ui", fontSize: 13, opacity: 0.8 }}>
                          {discordConnected
                            ? `Connected: ${discordLabel || "Discord"} • ID auto-filled`
                            : "Not connected"}
                        </Typography>
                      </Box>

                      <Stack direction="row" spacing={1}>
                        {!discordConnected ? (
                          <Button
                            variant="contained"
                            onClick={startDiscordConnect}
                            sx={{ fontFamily: '"Bangers", system-ui', letterSpacing: 0.6 }}
                          >
                            Connect Discord
                          </Button>
                        ) : (
                          <>
                            <Button variant="outlined" onClick={() => { loadDiscordSession(); loadDiscordProof(); }}>
                              Refresh
                            </Button>
                            <Button variant="text" onClick={disconnectDiscord}>
                              Disconnect
                            </Button>
                          </>
                        )}
                      </Stack>
                    </Stack>
                  </Paper>
                )}

                <Typography
                  sx={{
                    fontFamily: '"Bangers", system-ui',
                    letterSpacing: 0.6,
                    mt: 0.5,
                  }}
                >
                  Platform User ID
                </Typography>

                <Box
                  component="input"
                  value={platformUserId}
                  onChange={(e: any) => setPlatformUserId(e.target.value)}
                  placeholder="Discord/Telegram/etc user id"
                  style={{
                    width: "100%",
                    padding: "12px 12px",
                    borderRadius: 16,
                    border: "3px solid #0b1220",
                    outline: "none",
                    fontFamily: "system-ui",
                    background: "rgba(255,255,255,0.06)",
                    color: "rgba(255,255,255,0.92)",
                  }}
                />

                {spaceExists === false && (
                  <Paper
                    sx={{
                      p: 1.25,
                      background: "rgba(255,204,0,.12)",
                      borderStyle: "dashed",
                    }}
                  >
                    <Typography sx={{ fontFamily: "system-ui", fontSize: 13 }}>
                      Verification isn’t enabled for this community yet. Please
                      contact an admin.
                    </Typography>
                  </Paper>
                )}

                <Stack
                  direction={{ xs: "column", sm: "row" }}
                  spacing={1}
                  sx={{ mt: 0.5 }}
                >
                  <Button
                    variant="contained"
                    onClick={() =>
                      signLinkRequest().catch((e) =>
                        setError(String(e?.message || e))
                      )
                    }
                    disabled={!publicKey || !spaceSalt || !platformUserId.trim()}
                    sx={{ fontFamily: '"Bangers", system-ui', letterSpacing: 0.8 }}
                  >
                    Sign consent
                  </Button>

                  <Button
                    variant="outlined"
                    onClick={() =>
                      postToAttestor().catch((e) =>
                        setError(String(e?.message || e))
                      )
                    }
                    disabled={!publicKey || !spaceSalt || !platformUserId.trim()}
                    sx={{ fontFamily: '"Bangers", system-ui', letterSpacing: 0.6 }}
                  >
                    Submit
                  </Button>

                  <Button variant="text" onClick={() => refresh().catch(() => {})}>
                    Refresh
                  </Button>
                </Stack>
              </Stack>
            </Stack>

            {error && (
              <Paper
                sx={{
                  mt: 2,
                  p: 1.25,
                  background: "rgba(255,0,0,.10)",
                  borderColor: "rgba(220,38,38,.7)",
                }}
              >
                <Typography sx={{ fontFamily: "system-ui", color: "#ff8fa3" }}>
                  {error}
                </Typography>
              </Paper>
            )}

            {msg && (
              <Paper sx={{ mt: 2, p: 1.25, background: "rgba(0,0,0,.25)" }}>
                <Typography
                  component="pre"
                  sx={{
                    whiteSpace: "pre-wrap",
                    m: 0,
                    fontFamily:
                      '"Roboto Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
                    fontSize: 12,
                  }}
                >
                  {msg}
                </Typography>
              </Paper>
            )}
          </Paper>
        )}

        {/* ===========================
            ADVANCED MODE
           =========================== */}
        {advancedMode && (
          <>
            <Paper sx={{ p: 2.5, mt: 2.5 }}>
              <Stack
                direction="row"
                justifyContent="space-between"
                alignItems="center"
                spacing={2}
              >
                <Box>
                  <Typography variant="h3">Advanced Tools</Typography>
                  <Typography
                    variant="body2"
                    sx={{ opacity: 0.78, fontFamily: "system-ui" }}
                  >
                    PDAs, hashes, and space setup.
                  </Typography>
                </Box>

                <Button
                  onClick={() => setAdvancedOpen((v) => !v)}
                  endIcon={
                    <ExpandMoreIcon
                      sx={{
                        transform: advancedOpen
                          ? "rotate(180deg)"
                          : "rotate(0deg)",
                      }}
                    />
                  }
                  sx={{
                    borderRadius: 999,
                    px: 2,
                    fontFamily: '"Bangers", system-ui',
                    letterSpacing: 0.6,
                    background: "rgba(255,255,255,0.08)",
                    border: "2px solid rgba(255,255,255,0.14)",
                    color: "rgba(255,255,255,0.92)",
                    "&:hover": { background: "rgba(255,255,255,0.12)" },
                  }}
                >
                  {advancedOpen ? "Hide" : "Show"}
                </Button>
              </Stack>
            </Paper>

            {advancedOpen && (
              <>
                {/* Layout (NO MUI Grid): CSS grid */}
                <Box
                  sx={{
                    mt: 2.5,
                    display: "grid",
                    gap: 2.5,
                    gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" },
                    alignItems: "start",
                  }}
                >
                  {/* SPACE */}
                  <Paper sx={{ p: 2.5 }}>
                    <Typography variant="h3">Space</Typography>
                    <Typography
                      variant="body2"
                      sx={{ mt: 0.5, opacity: 0.75, fontFamily: "system-ui" }}
                    >
                      Space config PDA (per DAO): contains salt + attestor + frozen
                      flag.
                    </Typography>

                    <Divider sx={{ my: 2 }} />

                    <Stack spacing={1.25}>
                      <Typography
                        sx={{
                          fontFamily: "system-ui",
                          fontSize: 12,
                          opacity: 0.7,
                        }}
                      >
                        DAO ID
                      </Typography>

                      <Box
                        component="input"
                        value={daoIdStr}
                        onChange={(e: any) => setDaoIdStr(e.target.value)}
                        placeholder="DAO pubkey"
                        style={{
                          width: "100%",
                          padding: "12px 12px",
                          borderRadius: 16,
                          border: "3px solid #0b1220",
                          outline: "none",
                          fontFamily: "system-ui",
                          background: "rgba(255,255,255,0.06)",
                          color: "rgba(255,255,255,0.92)",
                        }}
                      />

                      <InfoRow label="Space PDA" value={spacePda?.toBase58() || "—"} mono />
                      <InfoRow
                        label="Account"
                        value={
                          spaceExists == null
                            ? "—"
                            : spaceExists
                            ? "✅ exists"
                            : "❌ missing"
                        }
                      />
                      <InfoRow
                        label="Frozen"
                        value={
                          spaceFrozen == null ? "—" : spaceFrozen ? "✅ yes" : "❌ no"
                        }
                      />
                      <InfoRow
                        label="Salt (hex)"
                        value={spaceSalt ? bytesToHex(spaceSalt) : "—"}
                        mono
                      />

                      {!spaceExists && spacePda && (
                        <Paper
                          sx={{
                            mt: 1,
                            p: 1.25,
                            background: "rgba(255,204,0,.16)",
                            borderStyle: "dashed",
                          }}
                        >
                          <Typography sx={{ fontFamily: "system-ui", fontSize: 13 }}>
                            Space account not found. Initialize the Space on-chain
                            for this DAO first.
                          </Typography>
                        </Paper>
                      )}

                      {spaceExists === false && (
                        <Stack
                          direction={{ xs: "column", sm: "row" }}
                          spacing={1}
                          sx={{ mt: 1 }}
                        >
                          <Button
                            variant="contained"
                            onClick={() => setSpaceDialogOpen(true)}
                            sx={{
                              fontFamily: '"Bangers", system-ui',
                              letterSpacing: 0.7,
                            }}
                          >
                            Create Space…
                          </Button>
                          <Button variant="outlined" onClick={() => refresh().catch(() => {})}>
                            Refresh
                          </Button>
                        </Stack>
                      )}
                    </Stack>
                  </Paper>

                  {/* IDENTITY */}
                  <Paper sx={{ p: 2.5 }}>
                    <Typography variant="h3">Identity</Typography>
                    <Typography
                      variant="body2"
                      sx={{ mt: 0.5, opacity: 0.75, fontFamily: "system-ui" }}
                    >
                      Identity PDA: (space, platform, id_hash). Stores only hashed
                      ID + attestation info.
                    </Typography>

                    <Divider sx={{ my: 2 }} />

                    <Stack spacing={1.25}>
                      <Typography
                        sx={{
                          fontFamily: "system-ui",
                          fontSize: 12,
                          opacity: 0.7,
                        }}
                      >
                        Platform
                      </Typography>

                      <Box
                        component="select"
                        value={platform}
                        onChange={(e: any) => setPlatform(e.target.value)}
                        style={{
                          width: "100%",
                          padding: "12px 12px",
                          borderRadius: 16,
                          border: "3px solid #0b1220",
                          outline: "none",
                          fontFamily: "system-ui",
                          background: "rgba(255,255,255,0.06)",
                          color: "rgba(255,255,255,0.92)",
                        }}
                      >
                        <option value="discord">Discord</option>
                        <option value="telegram">Telegram</option>
                        <option value="twitter">Twitter</option>
                        <option value="email">Email</option>
                      </Box>

                      <Typography
                        sx={{
                          fontFamily: "system-ui",
                          fontSize: 12,
                          opacity: 0.7,
                          mt: 1,
                        }}
                      >
                        Platform User ID (temporary for MVP)
                      </Typography>

                      <Box
                        component="input"
                        value={platformUserId}
                        onChange={(e: any) => setPlatformUserId(e.target.value)}
                        placeholder="Discord/Telegram/etc user id"
                        style={{
                          width: "100%",
                          padding: "12px 12px",
                          borderRadius: 16,
                          border: "3px solid #0b1220",
                          outline: "none",
                          fontFamily: "system-ui",
                          background: "rgba(255,255,255,0.06)",
                          color: "rgba(255,255,255,0.92)",
                        }}
                      />

                      <InfoRow label="id_hash (hex)" value={bytesToHex(idHashBytes)} mono />
                      <InfoRow label="Identity PDA" value={identityPda?.toBase58() || "—"} mono />
                      <InfoRow
                        label="Account"
                        value={
                          identityExists == null
                            ? "—"
                            : identityExists
                            ? "✅ exists"
                            : "❌ missing"
                        }
                      />
                      <InfoRow label="Status" value={identityStatus} />

                      {identityInfo && (
                        <>
                          <InfoRow label="Verified at" value={fmtTs(identityInfo.verifiedAt)} />
                          <InfoRow
                            label="Expires at"
                            value={identityInfo.expiresAt ? fmtTs(identityInfo.expiresAt) : "No expiry"}
                          />
                          <InfoRow
                            label="Attested by"
                            value={identityInfo.attestedBy.toBase58()}
                            mono
                          />
                        </>
                      )}
                    </Stack>
                  </Paper>
                </Box>

                {/* WALLET LINKING */}
                <Paper sx={{ p: 2.5, mt: 2.5 }}>
                  <Typography variant="h3">Wallet Linking</Typography>
                  <Typography
                    variant="body2"
                    sx={{ mt: 0.5, opacity: 0.75, fontFamily: "system-ui" }}
                  >
                    Wallet signs consent → attestor verifies → attestor submits
                    on-chain link.
                  </Typography>

                  <Divider sx={{ my: 2 }} />

                  <Box
                    sx={{
                      display: "grid",
                      gridTemplateColumns: { xs: "1fr", md: "1.3fr 0.9fr" },
                      gap: 2,
                      alignItems: "start",
                    }}
                  >
                    <Stack spacing={1.1}>
                      <InfoRow label="Connected wallet" value={b58(publicKey)} mono />
                      <InfoRow
                        label="wallet_hash (hex)"
                        value={bytesToHex(walletHashBytes)}
                        mono
                      />
                      <InfoRow label="Link PDA" value={linkPda?.toBase58() || "—"} mono />
                      <InfoRow
                        label="Link"
                        value={
                          linkExists == null ? "—" : linkExists ? "✅ exists" : "❌ missing"
                        }
                      />
                      {linkInfo && <InfoRow label="Linked at" value={fmtTs(linkInfo.linkedAt)} />}
                    </Stack>

                    <Stack spacing={1.25}>
                      <Button
                        variant="contained"
                        onClick={() =>
                          signLinkRequest().catch((e) =>
                            setError(String(e?.message || e))
                          )
                        }
                        disabled={!publicKey || !spaceSalt || !platformUserId.trim()}
                      >
                        Sign consent (wallet)
                      </Button>

                      <Button
                        variant="outlined"
                        onClick={() =>
                          postToAttestor().catch((e) =>
                            setError(String(e?.message || e))
                          )
                        }
                        disabled={!publicKey || !spaceSalt || !platformUserId.trim()}
                      >
                        Submit to attestor API
                      </Button>

                      <Button variant="text" onClick={() => refresh().catch(() => {})}>
                        Refresh
                      </Button>

                      <Paper
                        sx={{
                          p: 1.25,
                          background: "rgba(38,198,255,.10)",
                          borderStyle: "dashed",
                        }}
                      >
                        <Typography sx={{ fontFamily: "system-ui", fontSize: 12 }}>
                          <b>Note:</b> Linking requires the on-chain <i>attestor</i>{" "}
                          to sign txs. This UI prepares the signed consent payload.
                        </Typography>
                      </Paper>
                    </Stack>
                  </Box>

                  {error && (
                    <Paper
                      sx={{
                        mt: 2,
                        p: 1.25,
                        background: "rgba(255,0,0,.10)",
                        borderColor: "rgba(220,38,38,.7)",
                      }}
                    >
                      <Typography sx={{ fontFamily: "system-ui", color: "#ff8fa3" }}>
                        {error}
                      </Typography>
                    </Paper>
                  )}

                  {msg && (
                    <Paper sx={{ mt: 2, p: 1.25, background: "rgba(0,0,0,.25)" }}>
                      <Typography
                        component="pre"
                        sx={{
                          whiteSpace: "pre-wrap",
                          m: 0,
                          fontFamily:
                            '"Roboto Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
                          fontSize: 12,
                        }}
                      >
                        {msg}
                      </Typography>
                    </Paper>
                  )}
                </Paper>
              </>
            )}

            <CreateSpaceDialog
              open={spaceDialogOpen}
              onClose={() => setSpaceDialogOpen(false)}
              daoIdStr={daoIdStr}
              onCreated={() => {
                refresh().catch(() => {});
                setSpaceDialogOpen(false);
              }}
            />
          </>
        )}
      </Container>
    </Box>
  );
}

function SimpleStep({
  n,
  title,
  detail,
  ok,
}: {
  n: number;
  title: string;
  detail: string;
  ok: boolean;
}) {
  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: { xs: "1fr", sm: "80px 1fr" },
        gap: 1.25,
        alignItems: "center",
        p: 1.25,
        borderRadius: 3,
        background: "rgba(255,255,255,0.06)",
        border: "2px solid rgba(255,255,255,0.10)",
      }}
    >
      <Box
        sx={{
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          width: 54,
          height: 54,
          borderRadius: 999,
          fontFamily: '"Bangers", system-ui',
          letterSpacing: 0.6,
          border: "3px solid #0b1220",
          boxShadow: "4px 4px 0 #0b1220",
          background: ok ? "rgba(34,197,94,0.25)" : "rgba(255,255,255,0.06)",
        }}
      >
        {n}
      </Box>

      <Box>
        <Typography
          sx={{
            fontFamily: '"Bangers", system-ui',
            letterSpacing: 0.6,
            fontSize: 18,
          }}
        >
          {title} {ok ? "✅" : ""}
        </Typography>
        <Typography sx={{ opacity: 0.78, fontFamily: "system-ui", fontSize: 13 }}>
          {detail}
        </Typography>
      </Box>
    </Box>
  );
}

function InfoRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: "140px 1fr",
        gap: 1.25,
        alignItems: "center",
      }}
    >
      <Typography sx={{ fontFamily: "system-ui", fontSize: 12, opacity: 0.7 }}>
        {label}
      </Typography>

      <Box
        sx={{
          px: 1.25,
          py: 1,
          borderRadius: 2,
          background: "rgba(255,255,255,0.06)",
          overflowX: "auto",
          fontFamily: mono
            ? '"Roboto Mono", ui-monospace, SFMono-Regular, Menlo, monospace'
            : "system-ui",
          fontSize: 12,
        }}
      >
        {value}
      </Box>
    </Box>
  );
}