"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Box,
  Button,
  Chip,
  Container,
  Divider,
  IconButton,
  Paper,
  Stack,
  Tooltip,
  Typography,
} from "@mui/material";

import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import LinkIcon from "@mui/icons-material/Link";
import LinkOffIcon from "@mui/icons-material/LinkOff";
import TravelExploreIcon from "@mui/icons-material/TravelExplore";
import TuneIcon from "@mui/icons-material/Tune";
import VerifiedIcon from "@mui/icons-material/Verified";
import WalletIcon from "@mui/icons-material/AccountBalanceWallet";

import { useConnection, useWallet } from "@solana/wallet-adapter-react";
import { Connection, PublicKey } from "@solana/web3.js";

import CreateSpaceDialog from "./components/CreateSpaceDialog";
import WalletComicButton from "./components/WalletComicButton";

import {
  PROGRAM_ID,
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
import TelegramLoginButton from "./components/TelegramLoginButton";

type PlatformKey = "discord" | "telegram" | "twitter" | "email";

/* ---------- parsed Link account returned by getProgramAccounts ---------- */
interface LinkedWallet {
  pubkey: PublicKey; // the Link PDA
  walletHashBytes: Uint8Array;
  walletHashHex: string;
  linkedAt: number;
  identity: PublicKey;
  isCurrentWallet: boolean; // true when walletHash matches the connected wallet
}

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

function shortHex(hex: string) {
  if (!hex || hex === "—" || hex.length < 12) return hex;
  return `${hex.slice(0, 6)}…${hex.slice(-6)}`;
}

function parseSpaceSalt(data: Uint8Array): Uint8Array {
  const SALT_OFFSET = 8 + 1 + 32 + 32 + 32 + 1 + 1; // 107
  return data.slice(SALT_OFFSET, SALT_OFFSET + 32);
}

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

/* =========================================================================
 * LINK ACCOUNT DISCRIMINATOR
 *
 * Anchor accounts are prefixed with sha256("account:LinkAccount")[0..8].
 * We use this to filter getProgramAccounts results.
 * ========================================================================= */
import { sha256 } from "@noble/hashes/sha256";
import { utf8ToBytes } from "@noble/hashes/utils";

const LINK_ACCOUNT_DISC = sha256(utf8ToBytes("account:LinkAccount")).slice(0, 8);

/* =========================================================================
 * Fetch ALL Link accounts for a given Identity PDA
 *
 * Link account layout (82 bytes):
 *   [0..8]   discriminator
 *   [8]      version (u8)
 *   [9..41]  identity (Pubkey, 32 bytes)   ← we filter on this
 *   [41..73] wallet_hash ([u8;32])
 *   [73..81] linked_at (i64 LE)
 *   [81]     bump (u8)
 * ========================================================================= */
async function fetchLinkedWallets(
  connection: Connection,
  identityPda: PublicKey,
  currentWalletHash: Uint8Array | null
): Promise<LinkedWallet[]> {
  try {
    const accounts = await connection.getProgramAccounts(PROGRAM_ID, {
      filters: [
        { memcmp: { offset: 0, bytes: Buffer.from(LINK_ACCOUNT_DISC).toString("base64"), encoding: "base64" } },
        { memcmp: { offset: 9, bytes: identityPda.toBase58() } },
      ],
    });

    const currentHex = currentWalletHash ? bytesToHex(currentWalletHash) : null;

    return accounts
      .map((a) => {
        const parsed = parseLink(a.account.data);
        const whHex = bytesToHex(parsed.walletHashBytes);
        return {
          pubkey: a.pubkey,
          walletHashBytes: parsed.walletHashBytes,
          walletHashHex: whHex,
          linkedAt: parsed.linkedAt,
          identity: parsed.identity,
          isCurrentWallet: currentHex !== null && whHex === currentHex,
        };
      })
      .sort((a, b) => a.linkedAt - b.linkedAt);
  } catch (e) {
    console.error("fetchLinkedWallets error:", e);
    return [];
  }
}

export default function Page() {
  const { connection } = useConnection();
  const { publicKey, signMessage } = useWallet();

  // Mode state
  const [advancedMode, setAdvancedMode] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);

  // Discord state
  const [discordConnected, setDiscordConnected] = useState(false);
  const [discordLabel, setDiscordLabel] = useState<string | null>(null);
  const [discordProof, setDiscordProof] = useState<string | null>(null);

  // Email state
  const [emailConnected, setEmailConnected] = useState(false);
  const [emailAddress, setEmailAddress] = useState<string | null>(null);
  const [emailProof, setEmailProof] = useState<string | null>(null);
  const [emailInput, setEmailInput] = useState("");
  const [emailCodeSent, setEmailCodeSent] = useState(false);
  const [emailCode, setEmailCode] = useState("");
  const [emailSending, setEmailSending] = useState(false);
  const [emailVerifying, setEmailVerifying] = useState(false);

  // Telegram state
  const [telegramConnected, setTelegramConnected] = useState(false);
  const [telegramLabel, setTelegramLabel] = useState<string | null>(null);
  const [telegramProof, setTelegramProof] = useState<string | null>(null);
  const [showTelegramWidget, setShowTelegramWidget] = useState(false);

  // Core state
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

  const [walletHashBytes, setWalletHashBytes] = useState<Uint8Array | null>(null);
  const [linkPda, setLinkPda] = useState<PublicKey | null>(null);
  const [linkExists, setLinkExists] = useState<boolean | null>(null);
  const [linkInfo, setLinkInfo] = useState<ReturnType<typeof parseLink> | null>(null);

  // Multi-wallet state
  const [linkedWallets, setLinkedWallets] = useState<LinkedWallet[]>([]);
  const [linkedWalletsLoading, setLinkedWalletsLoading] = useState(false);
  const [unlinkingWallet, setUnlinkingWallet] = useState<string | null>(null); // walletHashHex being unlinked

  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");
  const [spaceDialogOpen, setSpaceDialogOpen] = useState(false);
  const [refreshCounter, setRefreshCounter] = useState(0);

  // Load mode from localStorage
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

  // Discord functions
  async function loadDiscordSession() {
    try {
      const me = await fetch("/api/discord/me", { cache: "no-store" }).then((r) =>
        r.json()
      );
      setDiscordConnected(!!me?.connected);
      setDiscordLabel(me?.label || null);

      if (me?.connected && me?.id && platform === "discord") {
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
      typeof window !== "undefined"
        ? window.location.pathname + window.location.search
        : "/";
    window.location.href = `/api/discord/start?returnTo=${encodeURIComponent(
      returnTo
    )}`;
  }

  async function disconnectDiscord() {
    await fetch("/api/discord/disconnect", { method: "POST" }).catch(() => {});
    setDiscordConnected(false);
    setDiscordLabel(null);
    setDiscordProof(null);
    if (platform === "discord") setPlatformUserId("");
  }

  // Email functions
  async function loadEmailSession() {
    try {
      const me = await fetch("/api/email/me", { cache: "no-store" }).then((r) =>
        r.json()
      );
      setEmailConnected(!!me?.connected);
      setEmailAddress(me?.email || null);

      if (me?.connected && me?.id && platform === "email") {
        setPlatformUserId(String(me.id));
      }
    } catch {
      setEmailConnected(false);
      setEmailAddress(null);
    }
  }

  async function loadEmailProof() {
    try {
      const r = await fetch("/api/email/proof", { cache: "no-store" });
      const j = await r.json();
      if (j?.connected && j?.proof) setEmailProof(j.proof);
      else setEmailProof(null);
    } catch {
      setEmailProof(null);
    }
  }

  async function sendEmailCode() {
    setError("");
    setEmailSending(true);

    try {
      await fetch(
        `/api/email/start?returnTo=${encodeURIComponent(window.location.pathname)}`
      );

      const res = await fetch("/api/email/send-code", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: emailInput }),
      });

      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.error || "Failed to send code");
      }

      setEmailCodeSent(true);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setEmailSending(false);
    }
  }

  async function verifyEmailCode() {
    setError("");
    setEmailVerifying(true);

    try {
      const res = await fetch("/api/email/verify-code", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code: emailCode }),
      });

      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.error || "Invalid code");
      }

      const data = await res.json();
      setEmailConnected(true);
      setEmailAddress(data.email);
      setPlatformUserId(data.userId);
      setEmailCodeSent(false);
      setEmailCode("");
      setEmailInput("");

      await loadEmailProof();
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setEmailVerifying(false);
    }
  }

  async function disconnectEmail() {
    await fetch("/api/email/disconnect", { method: "POST" }).catch(() => {});
    setEmailConnected(false);
    setEmailAddress(null);
    setEmailProof(null);
    setEmailCodeSent(false);
    setEmailCode("");
    if (platform === "email") setPlatformUserId("");
  }

  // Telegram functions
  async function loadTelegramSession() {
    try {
      const me = await fetch("/api/telegram/me", { cache: "no-store" }).then((r) =>
        r.json()
      );
      setTelegramConnected(!!me?.connected);
      setTelegramLabel(me?.label || null);

      if (me?.connected && me?.id && platform === "telegram") {
        setPlatformUserId(String(me.id));
      }
    } catch {
      setTelegramConnected(false);
      setTelegramLabel(null);
    }
  }

  async function loadTelegramProof() {
    try {
      const r = await fetch("/api/telegram/proof", { cache: "no-store" });
      const j = await r.json();
      if (j?.connected && j?.proof) setTelegramProof(j.proof);
      else setTelegramProof(null);
    } catch {
      setTelegramProof(null);
    }
  }

  async function handleTelegramAuth(user: any) {
    try {
      const res = await fetch("/api/telegram/callback", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(user),
      });

      if (res.ok) {
        await loadTelegramSession();
        await loadTelegramProof();
        setShowTelegramWidget(false);
      } else {
        const err = await res.json();
        setError(err.error || "Telegram auth failed");
      }
    } catch (e: any) {
      setError(String(e?.message || e));
    }
  }

  async function disconnectTelegram() {
    await fetch("/api/telegram/disconnect", { method: "POST" }).catch(() => {});
    setTelegramConnected(false);
    setTelegramLabel(null);
    setTelegramProof(null);
    if (platform === "telegram") setPlatformUserId("");
  }

  // Load platform sessions
  useEffect(() => {
    if (platform === "discord") {
      loadDiscordSession();
      loadDiscordProof();
    } else if (platform === "email") {
      loadEmailSession();
      loadEmailProof();
    } else if (platform === "telegram") {
      loadTelegramSession();
      loadTelegramProof();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [platform]);

  const daoPk = useMemo(() => {
    try {
      const s = daoIdStr.trim();
      if (!s) return null;
      return new PublicKey(s);
    } catch {
      return null;
    }
  }, [daoIdStr]);

  // Load Space PDA + account
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
      setLinkedWallets([]);

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
  }, [connection, daoPk, refreshCounter]);

  // Derive Identity + Link and load accounts + all linked wallets
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
      setLinkedWallets([]);

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

      // Compute current wallet hash (if wallet connected)
      let wh: Uint8Array | null = null;
      if (publicKey) {
        wh = walletHash(spaceSalt, publicKey);
        setWalletHashBytes(wh);

        const [lPda] = deriveLinkPda(idPda, wh);
        setLinkPda(lPda);

        const lAcct = await safeGetAccountInfo(connection, lPda);
        if (cancelled) return;

        setLinkExists(!!lAcct);
        setLinkInfo(lAcct ? parseLink(lAcct.data) : null);
      }

      // Fetch ALL linked wallets for this identity
      if (idAcct) {
        setLinkedWalletsLoading(true);
        const wallets = await fetchLinkedWallets(connection, idPda, wh);
        if (!cancelled) {
          setLinkedWallets(wallets);
          setLinkedWalletsLoading(false);
        }
      }
    }

    run().catch((e) => setError(String(e?.message || e)));
    return () => {
      cancelled = true;
    };
  }, [
    connection,
    spacePda,
    spaceSalt,
    platform,
    platformUserId,
    publicKey,
    refreshCounter,
  ]);

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
    setRefreshCounter((c) => c + 1);
  }

  // ===========================
  // One-click LINK
  // ===========================
  async function linkWalletOneClick() {
    setError("");
    setMsg("Processing...");

    try {
      if (!signMessage) {
        throw new Error("Wallet does not support signMessage (try Phantom/Solflare)");
      }
      if (!daoPk || !spacePda || !spaceSalt) {
        throw new Error("Missing DAO/space. Ensure Space exists on-chain.");
      }
      if (!publicKey) {
        throw new Error("Connect wallet first");
      }
      if (!platformUserId.trim()) {
        throw new Error("Platform ID required");
      }

      const idh =
        idHashBytes ??
        identityHash(spaceSalt, platformTag(platform), platformUserId.trim());
      const wh = walletHashBytes ?? walletHash(spaceSalt, publicKey);

      if (!idHashBytes) setIdHashBytes(idh);
      if (!walletHashBytes) setWalletHashBytes(wh);

      // Get platform proof automatically
      let platformProofValue = null;
      if (platform === "discord" && discordProof) {
        platformProofValue = discordProof;
      } else if (platform === "email" && emailProof) {
        platformProofValue = emailProof;
      } else if (platform === "telegram" && telegramProof) {
        platformProofValue = telegramProof;
      }

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
          `platform=${payload.platform}\n` +
          `wallet=${payload.wallet}\n` +
          `ts=${payload.ts}`
      );

      const sig = await signMessage(message);
      const sigB64 = btoa(String.fromCharCode(...sig));

      const res = await fetch(`/api/attestor/link`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ payload, signatureBase64: sigB64 }),
      });

      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.error || `Error: ${res.status}`);
      }

      const result = await res.json();

      setMsg(
        `✅ Successfully linked! Transaction: ${result.signature || "complete"}`
      );

      // Auto-refresh to pick up the new on-chain state
      setTimeout(() => refresh(), 2000);
    } catch (e: any) {
      setError(String(e?.message || e));
      setMsg("");
    }
  }

  // ===========================
  // UNLINK wallet
  // ===========================
  async function unlinkWallet(targetWalletHashHex: string) {
    setError("");
    setMsg("Unlinking...");
    setUnlinkingWallet(targetWalletHashHex);

    try {
      if (!signMessage) {
        throw new Error("Wallet does not support signMessage (try Phantom/Solflare)");
      }
      if (!daoPk || !spacePda || !spaceSalt) {
        throw new Error("Missing DAO/space.");
      }
      if (!publicKey) {
        throw new Error("Connect wallet first");
      }
      if (!platformUserId.trim()) {
        throw new Error("Platform ID required");
      }

      const idh =
        idHashBytes ??
        identityHash(spaceSalt, platformTag(platform), platformUserId.trim());

      // Get platform proof
      let platformProofValue = null;
      if (platform === "discord" && discordProof) {
        platformProofValue = discordProof;
      } else if (platform === "email" && emailProof) {
        platformProofValue = emailProof;
      } else if (platform === "telegram" && telegramProof) {
        platformProofValue = telegramProof;
      }

      const payload = {
        daoId: daoPk.toBase58(),
        platform,
        platformSeed: platformSeed(platform),
        platformUserId: platformUserId.trim(),
        platformProof: platformProofValue,
        idHashHex: bytesToHex(idh),
        walletHashHex: targetWalletHashHex,
        wallet: publicKey.toBase58(),
        ts: Date.now(),
        space: spacePda.toBase58(),
      };

      const message = new TextEncoder().encode(
        `Grape Verification Unlink Request\n` +
          `platform=${payload.platform}\n` +
          `wallet=${payload.wallet}\n` +
          `walletHash=${targetWalletHashHex}\n` +
          `ts=${payload.ts}`
      );

      const sig = await signMessage(message);
      const sigB64 = btoa(String.fromCharCode(...sig));

      const res = await fetch(`/api/attestor/unlink`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ payload, signatureBase64: sigB64 }),
      });

      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.error || `Error: ${res.status}`);
      }

      const result = await res.json();

      setMsg(
        `✅ Successfully unlinked! Transaction: ${result.signature || "complete"}`
      );

      setTimeout(() => refresh(), 2000);
    } catch (e: any) {
      setError(String(e?.message || e));
      setMsg("");
    } finally {
      setUnlinkingWallet(null);
    }
  }

  // Legacy functions (kept for advanced mode)
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
      setError("Enter a platform user id.");
      return;
    }

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
        `Payload:\n${JSON.stringify(payload, null, 2)}\n\n` +
        `Signature (base64):\n${sigB64}`
    );
  }

  async function postToAttestor() {
    setError("");
    setMsg("");

    if (!signMessage) {
      setError("Wallet does not support signMessage.");
      return;
    }
    if (!daoPk || !spacePda || !spaceSalt || !publicKey) {
      setError("Missing DAO/space/wallet. Ensure Space exists and wallet connected.");
      return;
    }
    if (!platformUserId.trim()) {
      setError("Enter a platform user id.");
      return;
    }

    const idh =
      idHashBytes ??
      identityHash(spaceSalt, platformTag(platform), platformUserId.trim());
    const wh = walletHashBytes ?? walletHash(spaceSalt, publicKey);

    if (!idHashBytes) setIdHashBytes(idh);
    if (!walletHashBytes) setWalletHashBytes(wh);

    const platformProofValue =
      platform === "discord"
        ? discordProof || null
        : platform === "email"
        ? emailProof || null
        : platform === "telegram"
        ? telegramProof || null
        : null;

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
      ? `Link: exists (${linkedWallets.length} wallet${linkedWallets.length !== 1 ? "s" : ""})`
      : "Link: missing";

  const simpleSteps = useMemo(() => {
    const walletOk = !!publicKey;
    const spaceOk = spaceExists === true;
    const platformOk =
      (platform === "discord" && discordConnected) ||
      (platform === "email" && emailConnected) ||
      (platform === "telegram" && telegramConnected);
    const verifiedOk =
      identityInfo?.verified === true && identityStatus.startsWith("Verified");
    const linkOk = linkExists === true;

    return { walletOk, spaceOk, platformOk, verifiedOk, linkOk };
  }, [
    publicKey,
    spaceExists,
    platform,
    discordConnected,
    emailConnected,
    telegramConnected,
    identityInfo,
    identityStatus,
    linkExists,
  ]);

  // Current wallet already linked?
  const currentWalletLinked = linkExists === true;

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
                  src="/grape-touch.png"
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
                  Mainnet • Privacy-preserving identity ↔ wallet linking
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
              sx={{ opacity: 0.78, fontFamily: "system-ui", mb: 2 }}
            >
              Choose your platform, connect, then link your wallet. You can link
              multiple wallets to the same identity.
            </Typography>

            {/* Step 1: Platform Selection & Connection */}
            <Box
              sx={{
                p: 2,
                borderRadius: 2,
                background: "rgba(255,255,255,0.04)",
                border: "2px solid rgba(255,255,255,0.08)",
                mb: 2,
              }}
            >
              <Typography
                sx={{
                  fontFamily: '"Bangers", system-ui',
                  letterSpacing: 0.6,
                  mb: 1.5,
                  fontSize: 16,
                }}
              >
                Step 1: Connect Platform
              </Typography>

              {/* Platform Tabs */}
              <Stack
                direction="row"
                spacing={1}
                sx={{ mb: 2 }}
                flexWrap="wrap"
                useFlexGap
              >
                {(["discord", "email", "telegram", "twitter"] as const).map(
                  (p) => (
                    <Button
                      key={p}
                      onClick={() => setPlatform(p)}
                      variant={platform === p ? "contained" : "outlined"}
                      sx={{
                        fontFamily: '"Bangers", system-ui',
                        letterSpacing: 0.6,
                        textTransform: "capitalize",
                        minWidth: 100,
                      }}
                    >
                      {p}
                    </Button>
                  )
                )}
              </Stack>

              {/* Platform-Specific Connection UI */}
              {platform === "discord" && (
                <PlatformConnectionCard
                  platform="Discord"
                  connected={discordConnected}
                  label={discordLabel}
                  onConnect={startDiscordConnect}
                  onDisconnect={disconnectDiscord}
                  onRefresh={() => {
                    loadDiscordSession();
                    loadDiscordProof();
                  }}
                />
              )}

              {platform === "email" && (
                <EmailConnectionCard
                  connected={emailConnected}
                  email={emailAddress}
                  emailInput={emailInput}
                  setEmailInput={setEmailInput}
                  emailCodeSent={emailCodeSent}
                  emailCode={emailCode}
                  setEmailCode={setEmailCode}
                  emailSending={emailSending}
                  emailVerifying={emailVerifying}
                  sendCode={sendEmailCode}
                  verifyCode={verifyEmailCode}
                  disconnect={disconnectEmail}
                  onRefresh={() => {
                    loadEmailSession();
                    loadEmailProof();
                  }}
                  onCancel={() => {
                    setEmailCodeSent(false);
                    setEmailCode("");
                  }}
                />
              )}

              {platform === "telegram" && (
                <TelegramConnectionCard
                  connected={telegramConnected}
                  label={telegramLabel}
                  onConnect={() => setShowTelegramWidget(true)}
                  onDisconnect={disconnectTelegram}
                  onRefresh={() => {
                    loadTelegramSession();
                    loadTelegramProof();
                  }}
                  onAuth={handleTelegramAuth}
                  showWidget={showTelegramWidget}
                  botUsername={
                    process.env.NEXT_PUBLIC_TELEGRAM_BOT_USERNAME || ""
                  }
                />
              )}

              {platform === "twitter" && (
                <Paper
                  sx={{
                    p: 2,
                    background: "rgba(255,255,255,0.06)",
                    border: "2px solid rgba(255,255,255,0.10)",
                  }}
                >
                  <Typography
                    sx={{ fontFamily: "system-ui", fontSize: 14, opacity: 0.9 }}
                  >
                    Twitter verification coming soon!
                  </Typography>
                  <Typography
                    sx={{
                      fontFamily: "system-ui",
                      fontSize: 13,
                      opacity: 0.7,
                      mt: 0.5,
                    }}
                  >
                    For now, you can test with Discord, Telegram or Email.
                  </Typography>
                </Paper>
              )}
            </Box>

            {/* Step 2: Link Wallet (Only shows when platform connected) */}
            {((platform === "discord" && discordConnected) ||
              (platform === "email" && emailConnected) ||
              (platform === "telegram" && telegramConnected)) && (
              <Box
                sx={{
                  p: 2,
                  borderRadius: 2,
                  background: "rgba(34,197,94,0.08)",
                  border: "2px solid rgba(34,197,94,0.2)",
                  mb: 2,
                }}
              >
                <Typography
                  sx={{
                    fontFamily: '"Bangers", system-ui',
                    letterSpacing: 0.6,
                    mb: 1.5,
                    fontSize: 16,
                  }}
                >
                  Step 2: Link Your Wallet
                </Typography>

                {/* Status Summary */}
                <Stack spacing={1} sx={{ mb: 2 }}>
                  <StatusChip
                    label={`Wallet: ${
                      publicKey ? shortB58(publicKey) : "Not connected"
                    }`}
                    ok={!!publicKey}
                  />
                  <StatusChip
                    label={`Community: ${
                      spaceExists === true
                        ? "Ready"
                        : spaceExists === false
                        ? "Not enabled"
                        : "Checking..."
                    }`}
                    ok={spaceExists === true}
                  />
                  <StatusChip
                    label={`Identity: ${identityStatus}`}
                    ok={identityInfo?.verified === true}
                  />
                  <StatusChip
                    label={`This wallet: ${
                      currentWalletLinked ? "Linked" : "Not linked"
                    }`}
                    ok={currentWalletLinked}
                  />
                </Stack>

                {/* Primary Action Button */}
                <Button
                  variant="contained"
                  size="large"
                  fullWidth
                  onClick={() => linkWalletOneClick()}
                  disabled={
                    !publicKey ||
                    !spaceSalt ||
                    !platformUserId.trim() ||
                    currentWalletLinked ||
                    spaceExists === false
                  }
                  sx={{
                    fontFamily: '"Bangers", system-ui',
                    letterSpacing: 0.8,
                    fontSize: 18,
                    py: 1.5,
                    background: currentWalletLinked
                      ? "rgba(34,197,94,0.3)"
                      : "linear-gradient(135deg, #7c4dff 0%, #26c6ff 100%)",
                    "&:hover": {
                      background: currentWalletLinked
                        ? "rgba(34,197,94,0.3)"
                        : "linear-gradient(135deg, #6a3de8 0%, #1fa8e8 100%)",
                    },
                    "&:disabled": {
                      background: "rgba(255,255,255,0.1)",
                      color: "rgba(255,255,255,0.3)",
                    },
                  }}
                >
                  {currentWalletLinked
                    ? "✅ This Wallet Linked"
                    : spaceExists === false
                    ? "Community Not Enabled"
                    : !publicKey
                    ? "Connect Wallet First"
                    : linkedWallets.length > 0
                    ? "🔗 Link Additional Wallet"
                    : "🔗 Link Wallet Now"}
                </Button>

                {currentWalletLinked && linkedWallets.length > 0 && (
                  <Typography
                    sx={{
                      mt: 1,
                      textAlign: "center",
                      fontFamily: "system-ui",
                      fontSize: 13,
                      opacity: 0.7,
                    }}
                  >
                    Switch to a different wallet to link another one.
                  </Typography>
                )}

                {!publicKey && (
                  <Typography
                    sx={{
                      mt: 1.5,
                      textAlign: "center",
                      fontFamily: "system-ui",
                      fontSize: 13,
                      opacity: 0.7,
                    }}
                  >
                    ↑ Connect your wallet first (top right)
                  </Typography>
                )}

                {spaceExists === false && (
                  <Paper
                    sx={{
                      mt: 2,
                      p: 1.25,
                      background: "rgba(255,204,0,.12)",
                      borderStyle: "dashed",
                    }}
                  >
                    <Typography sx={{ fontFamily: "system-ui", fontSize: 13 }}>
                      Verification isn't enabled for this community yet. Please
                      contact an admin.
                    </Typography>
                  </Paper>
                )}
              </Box>
            )}

            {/* ===========================
                Linked Wallets List
               =========================== */}
            {linkedWallets.length > 0 && (
              <Box
                sx={{
                  p: 2,
                  borderRadius: 2,
                  background: "rgba(255,255,255,0.04)",
                  border: "2px solid rgba(255,255,255,0.08)",
                  mb: 2,
                }}
              >
                <Stack
                  direction="row"
                  justifyContent="space-between"
                  alignItems="center"
                  sx={{ mb: 1.5 }}
                >
                  <Typography
                    sx={{
                      fontFamily: '"Bangers", system-ui',
                      letterSpacing: 0.6,
                      fontSize: 16,
                    }}
                  >
                    <WalletIcon
                      sx={{ fontSize: 18, mr: 0.75, verticalAlign: "text-bottom" }}
                    />
                    Linked Wallets ({linkedWallets.length})
                  </Typography>
                  <Button
                    variant="text"
                    size="small"
                    onClick={() => refresh()}
                    sx={{ fontFamily: "system-ui", fontSize: 12 }}
                  >
                    Refresh
                  </Button>
                </Stack>

                <Stack spacing={1}>
                  {linkedWallets.map((lw) => (
                    <LinkedWalletRow
                      key={lw.walletHashHex}
                      wallet={lw}
                      onUnlink={() => unlinkWallet(lw.walletHashHex)}
                      unlinking={unlinkingWallet === lw.walletHashHex}
                      canUnlink={!!publicKey && !!signMessage}
                    />
                  ))}
                </Stack>

                {linkedWalletsLoading && (
                  <Typography
                    sx={{
                      fontFamily: "system-ui",
                      fontSize: 12,
                      opacity: 0.6,
                      mt: 1,
                    }}
                  >
                    Loading linked wallets...
                  </Typography>
                )}
              </Box>
            )}

            {/* Errors & Messages */}
            {error && (
              <Paper
                sx={{
                  mt: 2,
                  p: 1.5,
                  background: "rgba(255,0,0,.10)",
                  borderColor: "rgba(220,38,38,.7)",
                }}
              >
                <Typography
                  sx={{
                    fontFamily: "system-ui",
                    color: "#ff8fa3",
                    fontSize: 14,
                  }}
                >
                  ❌ {error}
                </Typography>
              </Paper>
            )}

            {msg && (
              <Paper
                sx={{
                  mt: 2,
                  p: 1.5,
                  background: msg.startsWith("✅")
                    ? "rgba(34,197,94,.10)"
                    : "rgba(0,0,0,.25)",
                  borderColor: msg.startsWith("✅")
                    ? "rgba(34,197,94,.5)"
                    : "transparent",
                }}
              >
                <Typography
                  sx={{
                    fontFamily: msg.startsWith("✅") ? "system-ui" : "monospace",
                    color: msg.startsWith("✅") ? "#86efac" : "inherit",
                    fontSize: 14,
                    whiteSpace: "pre-wrap",
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
                      sx={{
                        mt: 0.5,
                        opacity: 0.75,
                        fontFamily: "system-ui",
                      }}
                    >
                      Space config PDA (per DAO): contains salt + attestor +
                      frozen flag.
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

                      <InfoRow
                        label="Space PDA"
                        value={spacePda?.toBase58() || "—"}
                        mono
                      />
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
                          spaceFrozen == null
                            ? "—"
                            : spaceFrozen
                            ? "✅ yes"
                            : "❌ no"
                        }
                      />
                      <InfoRow
                        label="Salt (hex)"
                        value={spaceSalt ? bytesToHex(spaceSalt) : "—"}
                        mono
                      />

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
                          <Button
                            variant="outlined"
                            onClick={() => refresh().catch(() => {})}
                          >
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
                      sx={{
                        mt: 0.5,
                        opacity: 0.75,
                        fontFamily: "system-ui",
                      }}
                    >
                      Identity PDA: (space, platform, id_hash). Stores only
                      hashed ID + attestation info.
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
                        Platform User ID
                      </Typography>

                      <Box
                        component="input"
                        value={platformUserId}
                        onChange={(e: any) =>
                          setPlatformUserId(e.target.value)
                        }
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

                      <InfoRow
                        label="id_hash (hex)"
                        value={bytesToHex(idHashBytes)}
                        mono
                      />
                      <InfoRow
                        label="Identity PDA"
                        value={identityPda?.toBase58() || "—"}
                        mono
                      />
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
                          <InfoRow
                            label="Verified at"
                            value={fmtTs(identityInfo.verifiedAt)}
                          />
                          <InfoRow
                            label="Expires at"
                            value={
                              identityInfo.expiresAt
                                ? fmtTs(identityInfo.expiresAt)
                                : "No expiry"
                            }
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
                    on-chain link. Multiple wallets can be linked to one
                    identity.
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
                      <InfoRow
                        label="Connected wallet"
                        value={b58(publicKey)}
                        mono
                      />
                      <InfoRow
                        label="wallet_hash (hex)"
                        value={bytesToHex(walletHashBytes)}
                        mono
                      />
                      <InfoRow
                        label="Link PDA"
                        value={linkPda?.toBase58() || "—"}
                        mono
                      />
                      <InfoRow
                        label="This wallet link"
                        value={
                          linkExists == null
                            ? "—"
                            : linkExists
                            ? "✅ exists"
                            : "❌ missing"
                        }
                      />
                      <InfoRow
                        label="Total linked"
                        value={
                          linkedWalletsLoading
                            ? "Loading..."
                            : `${linkedWallets.length} wallet(s)`
                        }
                      />
                      {linkInfo && (
                        <InfoRow
                          label="Linked at"
                          value={fmtTs(linkInfo.linkedAt)}
                        />
                      )}
                    </Stack>

                    <Stack spacing={1.25}>
                      <Button
                        variant="contained"
                        onClick={() =>
                          signLinkRequest().catch((e) =>
                            setError(String(e?.message || e))
                          )
                        }
                        disabled={
                          !publicKey || !spaceSalt || !platformUserId.trim()
                        }
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
                        disabled={
                          !publicKey || !spaceSalt || !platformUserId.trim()
                        }
                      >
                        Submit to attestor API
                      </Button>

                      <Button
                        variant="text"
                        onClick={() => refresh().catch(() => {})}
                      >
                        Refresh
                      </Button>

                      <Paper
                        sx={{
                          p: 1.25,
                          background: "rgba(38,198,255,.10)",
                          borderStyle: "dashed",
                        }}
                      >
                        <Typography
                          sx={{ fontFamily: "system-ui", fontSize: 12 }}
                        >
                          <b>Note:</b> Linking requires the on-chain{" "}
                          <i>attestor</i> to sign txs. This UI prepares the
                          signed consent payload.
                        </Typography>
                      </Paper>
                    </Stack>
                  </Box>

                  {/* Linked Wallets Table (Advanced) */}
                  {linkedWallets.length > 0 && (
                    <>
                      <Divider sx={{ my: 2 }} />
                      <Typography
                        sx={{
                          fontFamily: '"Bangers", system-ui',
                          letterSpacing: 0.6,
                          fontSize: 16,
                          mb: 1.5,
                        }}
                      >
                        All Linked Wallets ({linkedWallets.length})
                      </Typography>

                      <Stack spacing={1}>
                        {linkedWallets.map((lw) => (
                          <LinkedWalletRow
                            key={lw.walletHashHex}
                            wallet={lw}
                            onUnlink={() => unlinkWallet(lw.walletHashHex)}
                            unlinking={
                              unlinkingWallet === lw.walletHashHex
                            }
                            canUnlink={!!publicKey && !!signMessage}
                            advanced
                          />
                        ))}
                      </Stack>
                    </>
                  )}

                  {error && (
                    <Paper
                      sx={{
                        mt: 2,
                        p: 1.25,
                        background: "rgba(255,0,0,.10)",
                        borderColor: "rgba(220,38,38,.7)",
                      }}
                    >
                      <Typography
                        sx={{ fontFamily: "system-ui", color: "#ff8fa3" }}
                      >
                        {error}
                      </Typography>
                    </Paper>
                  )}

                  {msg && (
                    <Paper
                      sx={{ mt: 2, p: 1.25, background: "rgba(0,0,0,.25)" }}
                    >
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

// ===========================
// Helper Components
// ===========================

function LinkedWalletRow({
  wallet,
  onUnlink,
  unlinking,
  canUnlink,
  advanced,
}: {
  wallet: LinkedWallet;
  onUnlink: () => void;
  unlinking: boolean;
  canUnlink: boolean;
  advanced?: boolean;
}) {
  return (
    <Box
      sx={{
        px: 1.5,
        py: 1,
        borderRadius: 2,
        background: wallet.isCurrentWallet
          ? "rgba(124,77,255,0.12)"
          : "rgba(255,255,255,0.04)",
        border: `2px solid ${
          wallet.isCurrentWallet
            ? "rgba(124,77,255,0.3)"
            : "rgba(255,255,255,0.08)"
        }`,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 1,
        flexWrap: "wrap",
      }}
    >
      <Stack direction="row" spacing={1.5} alignItems="center" sx={{ minWidth: 0, flex: 1 }}>
        <WalletIcon sx={{ fontSize: 16, opacity: 0.6, flexShrink: 0 }} />
        <Box sx={{ minWidth: 0 }}>
          <Typography
            sx={{
              fontFamily:
                '"Roboto Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
              fontSize: 12,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {advanced ? wallet.walletHashHex : shortHex(wallet.walletHashHex)}
            {wallet.isCurrentWallet && (
              <Chip
                label="current"
                size="small"
                sx={{
                  ml: 1,
                  height: 18,
                  fontSize: 10,
                  fontFamily: "system-ui",
                  background: "rgba(124,77,255,0.25)",
                  color: "#c4b5fd",
                }}
              />
            )}
          </Typography>
          <Typography
            sx={{ fontFamily: "system-ui", fontSize: 11, opacity: 0.55 }}
          >
            Linked {fmtTs(wallet.linkedAt)}
          </Typography>
        </Box>
      </Stack>

      <Tooltip title={canUnlink ? "Unlink this wallet" : "Connect wallet to unlink"}>
        <span>
          <IconButton
            size="small"
            onClick={onUnlink}
            disabled={!canUnlink || unlinking}
            sx={{
              color: "rgba(255,100,100,0.8)",
              "&:hover": {
                background: "rgba(255,100,100,0.15)",
                color: "#ff6b6b",
              },
              "&:disabled": { opacity: 0.3 },
            }}
          >
            {unlinking ? (
              <Typography sx={{ fontSize: 11, fontFamily: "system-ui" }}>
                …
              </Typography>
            ) : (
              <LinkOffIcon sx={{ fontSize: 18 }} />
            )}
          </IconButton>
        </span>
      </Tooltip>
    </Box>
  );
}

function PlatformConnectionCard({
  platform,
  connected,
  label,
  onConnect,
  onDisconnect,
  onRefresh,
}: {
  platform: string;
  connected: boolean;
  label: string | null;
  onConnect: () => void;
  onDisconnect: () => void;
  onRefresh: () => void;
}) {
  return (
    <Paper
      sx={{
        p: 2,
        background: connected
          ? "rgba(34,197,94,0.10)"
          : "rgba(255,255,255,0.06)",
        border: `2px solid ${
          connected ? "rgba(34,197,94,0.3)" : "rgba(255,255,255,0.10)"
        }`,
      }}
    >
      <Stack
        direction={{ xs: "column", sm: "row" }}
        spacing={2}
        alignItems="center"
        justifyContent="space-between"
      >
        <Box>
          <Typography
            sx={{
              fontFamily: '"Bangers", system-ui',
              letterSpacing: 0.6,
              fontSize: 16,
            }}
          >
            {platform} {connected && "✅"}
          </Typography>
          <Typography
            sx={{ fontFamily: "system-ui", fontSize: 13, opacity: 0.8 }}
          >
            {connected ? `Connected: ${label || platform}` : `Not connected`}
          </Typography>
        </Box>

        <Stack direction="row" spacing={1}>
          {!connected ? (
            <Button
              variant="contained"
              onClick={onConnect}
              sx={{
                fontFamily: '"Bangers", system-ui',
                letterSpacing: 0.6,
              }}
            >
              Connect {platform}
            </Button>
          ) : (
            <>
              <Button variant="outlined" size="small" onClick={onRefresh}>
                Refresh
              </Button>
              <Button variant="text" size="small" onClick={onDisconnect}>
                Disconnect
              </Button>
            </>
          )}
        </Stack>
      </Stack>
    </Paper>
  );
}

function TelegramConnectionCard({
  connected,
  label,
  onConnect,
  onDisconnect,
  onRefresh,
  onAuth,
  showWidget,
  botUsername,
}: {
  connected: boolean;
  label: string | null;
  onConnect: () => void;
  onDisconnect: () => void;
  onRefresh: () => void;
  onAuth: (user: any) => void;
  showWidget: boolean;
  botUsername: string;
}) {
  return (
    <Paper
      sx={{
        p: 2,
        background: connected
          ? "rgba(34,197,94,0.10)"
          : "rgba(255,255,255,0.06)",
        border: `2px solid ${
          connected ? "rgba(34,197,94,0.3)" : "rgba(255,255,255,0.10)"
        }`,
      }}
    >
      <Stack
        direction={{ xs: "column", sm: "row" }}
        spacing={2}
        alignItems="center"
        justifyContent="space-between"
      >
        <Box>
          <Typography
            sx={{
              fontFamily: '"Bangers", system-ui',
              letterSpacing: 0.6,
              fontSize: 16,
            }}
          >
            Telegram {connected && "✅"}
          </Typography>
          <Typography
            sx={{ fontFamily: "system-ui", fontSize: 13, opacity: 0.8 }}
          >
            {connected
              ? `Connected: ${label || "Telegram"}`
              : "Not connected"}
          </Typography>
        </Box>

        <Stack direction="row" spacing={1}>
          {!connected ? (
            showWidget && botUsername ? (
              <Box>
                <TelegramLoginButton
                  botUsername={botUsername}
                  onAuth={onAuth}
                />
              </Box>
            ) : (
              <Button
                variant="contained"
                onClick={onConnect}
                sx={{
                  fontFamily: '"Bangers", system-ui',
                  letterSpacing: 0.6,
                }}
              >
                Connect Telegram
              </Button>
            )
          ) : (
            <>
              <Button variant="outlined" size="small" onClick={onRefresh}>
                Refresh
              </Button>
              <Button variant="text" size="small" onClick={onDisconnect}>
                Disconnect
              </Button>
            </>
          )}
        </Stack>
      </Stack>
    </Paper>
  );
}

function EmailConnectionCard({
  connected,
  email,
  emailInput,
  setEmailInput,
  emailCodeSent,
  emailCode,
  setEmailCode,
  emailSending,
  emailVerifying,
  sendCode,
  verifyCode,
  disconnect,
  onRefresh,
  onCancel,
}: {
  connected: boolean;
  email: string | null;
  emailInput: string;
  setEmailInput: (v: string) => void;
  emailCodeSent: boolean;
  emailCode: string;
  setEmailCode: (v: string) => void;
  emailSending: boolean;
  emailVerifying: boolean;
  sendCode: () => void;
  verifyCode: () => void;
  disconnect: () => void;
  onRefresh: () => void;
  onCancel: () => void;
}) {
  if (connected) {
    return (
      <Paper
        sx={{
          p: 2,
          background: "rgba(34,197,94,0.10)",
          border: "2px solid rgba(34,197,94,0.3)",
        }}
      >
        <Stack
          direction={{ xs: "column", sm: "row" }}
          spacing={2}
          alignItems="center"
          justifyContent="space-between"
        >
          <Box>
            <Typography
              sx={{
                fontFamily: '"Bangers", system-ui',
                letterSpacing: 0.6,
                fontSize: 16,
              }}
            >
              Email ✅
            </Typography>
            <Typography
              sx={{ fontFamily: "system-ui", fontSize: 13, opacity: 0.8 }}
            >
              Verified: {email}
            </Typography>
          </Box>

          <Stack direction="row" spacing={1}>
            <Button variant="outlined" size="small" onClick={onRefresh}>
              Refresh
            </Button>
            <Button variant="text" size="small" onClick={disconnect}>
              Disconnect
            </Button>
          </Stack>
        </Stack>
      </Paper>
    );
  }

  if (!emailCodeSent) {
    return (
      <Paper
        sx={{
          p: 2,
          background: "rgba(255,255,255,0.06)",
          border: "2px solid rgba(255,255,255,0.10)",
        }}
      >
        <Typography
          sx={{
            fontFamily: '"Bangers", system-ui',
            letterSpacing: 0.6,
            fontSize: 16,
            mb: 1,
          }}
        >
          Email Verification
        </Typography>
        <Typography
          sx={{
            fontFamily: "system-ui",
            fontSize: 13,
            opacity: 0.8,
            mb: 2,
          }}
        >
          Enter your email to receive a verification code
        </Typography>

        <Stack direction="row" spacing={1}>
          <Box
            component="input"
            type="email"
            value={emailInput}
            onChange={(e: any) => setEmailInput(e.target.value)}
            placeholder="your@email.com"
            onKeyDown={(e: any) => {
              if (e.key === "Enter" && emailInput.trim()) sendCode();
            }}
            style={{
              flex: 1,
              padding: "10px 12px",
              borderRadius: 12,
              border: "2px solid #0b1220",
              outline: "none",
              fontFamily: "system-ui",
              background: "rgba(255,255,255,0.06)",
              color: "rgba(255,255,255,0.92)",
            }}
          />
          <Button
            variant="contained"
            onClick={sendCode}
            disabled={!emailInput.trim() || emailSending}
            sx={{
              fontFamily: '"Bangers", system-ui',
              letterSpacing: 0.6,
              minWidth: 120,
            }}
          >
            {emailSending ? "Sending..." : "Send Code"}
          </Button>
        </Stack>
      </Paper>
    );
  }

  return (
    <Paper
      sx={{
        p: 2,
        background: "rgba(255,204,0,0.10)",
        border: "2px solid rgba(255,204,0,0.3)",
      }}
    >
      <Typography
        sx={{
          fontFamily: '"Bangers", system-ui',
          letterSpacing: 0.6,
          fontSize: 16,
          mb: 1,
        }}
      >
        Enter Verification Code
      </Typography>
      <Typography
        sx={{ fontFamily: "system-ui", fontSize: 13, opacity: 0.8, mb: 2 }}
      >
        Code sent to <strong>{emailInput}</strong>
      </Typography>

      <Stack spacing={1.5}>
        <Stack direction="row" spacing={1}>
          <Box
            component="input"
            type="text"
            value={emailCode}
            onChange={(e: any) => setEmailCode(e.target.value)}
            placeholder="6-digit code"
            maxLength={6}
            onKeyDown={(e: any) => {
              if (e.key === "Enter" && emailCode.length === 6) verifyCode();
            }}
            style={{
              flex: 1,
              padding: "10px 12px",
              borderRadius: 12,
              border: "2px solid #0b1220",
              outline: "none",
              fontFamily: "system-ui",
              background: "rgba(255,255,255,0.06)",
              color: "rgba(255,255,255,0.92)",
              letterSpacing: 4,
              textAlign: "center",
              fontSize: 16,
            }}
          />
          <Button
            variant="contained"
            onClick={verifyCode}
            disabled={emailCode.length !== 6 || emailVerifying}
            sx={{
              fontFamily: '"Bangers", system-ui',
              letterSpacing: 0.6,
              minWidth: 120,
            }}
          >
            {emailVerifying ? "Verifying..." : "Verify"}
          </Button>
        </Stack>
        <Button variant="text" size="small" onClick={onCancel}>
          Change email
        </Button>
      </Stack>
    </Paper>
  );
}

function StatusChip({ label, ok }: { label: string; ok: boolean }) {
  return (
    <Box
      sx={{
        px: 1.5,
        py: 0.75,
        borderRadius: 2,
        background: ok ? "rgba(34,197,94,0.15)" : "rgba(255,255,255,0.06)",
        border: `2px solid ${
          ok ? "rgba(34,197,94,0.3)" : "rgba(255,255,255,0.10)"
        }`,
        display: "inline-flex",
        alignItems: "center",
      }}
    >
      <Typography sx={{ fontFamily: "system-ui", fontSize: 13 }}>
        {ok ? "✅" : "⏳"} {label}
      </Typography>
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
      <Typography
        sx={{ fontFamily: "system-ui", fontSize: 12, opacity: 0.7 }}
      >
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