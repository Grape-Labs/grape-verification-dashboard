"use client";

import React, { useEffect, useMemo, useState } from "react";
import {
  Box,
  Button,
  Chip,
  Dialog,
  DialogContent,
  Divider,
  Paper,
  Stack,
  Typography,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";

import { useConnection, useWallet } from "@solana/wallet-adapter-react";
import { PublicKey, Transaction } from "@solana/web3.js";

// ✅ NPM helpers (NO Anchor)
import {
  PROGRAM_ID,
  deriveSpacePda,
  buildInitializeSpaceIx,
} from "@grapenpm/grape-verification-registry";

type Props = {
  open: boolean;
  onClose: () => void;
  daoIdStr: string;
  onCreated?: () => void;
};

/* ---------------- helpers ---------------- */

function safePk(s: string | undefined | null): PublicKey | null {
  try {
    if (!s) return null;
    return new PublicKey(String(s).trim());
  } catch {
    return null;
  }
}

function bytesToHex(u8: Uint8Array | null) {
  if (!u8) return "—";
  return Array.from(u8)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomSalt32(): Uint8Array {
  const u8 = new Uint8Array(32);
  crypto.getRandomValues(u8);
  return u8;
}

/* ---------------- component ---------------- */

export default function CreateSpaceDialog({
  open,
  onClose,
  daoIdStr,
  onCreated,
}: Props) {
  const { connection } = useConnection();
  const wallet = useWallet();

  const [salt, setSalt] = useState<Uint8Array | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>("");

  const daoPk = useMemo(() => safePk(daoIdStr), [daoIdStr]);

  const spacePda = useMemo(() => {
    if (!daoPk) return null;
    const [pda] = deriveSpacePda(daoPk);
    return pda;
  }, [daoPk]);

  useEffect(() => {
    if (!open) {
      setErr("");
      setBusy(false);
    }
  }, [open]);

  function copy(text: string) {
    if (!text || text === "—") return;
    navigator.clipboard?.writeText(text).catch(() => {});
  }

  /* ---------------- create ---------------- */

  async function handleCreate() {
    setErr("");
    setBusy(true);

    try {
      if (!wallet.publicKey) throw new Error("Connect a wallet first.");
      if (!wallet.sendTransaction)
        throw new Error("Wallet adapter missing sendTransaction.");
      if (!daoPk) throw new Error("DAO ID is not a valid public key.");
      if (!spacePda)
        throw new Error("Could not derive Space PDA (check DAO ID).");

      const saltBytes = salt ?? randomSalt32();
      setSalt(saltBytes);

      // 🔹 Build instruction (deterministic, no Anchor)
      const { ix } = buildInitializeSpaceIx({
        daoId: daoPk,
        salt: saltBytes,
        authority: wallet.publicKey,
        payer: wallet.publicKey,
        programId: PROGRAM_ID, // explicit & safe
      });

      const tx = new Transaction().add(ix);
      tx.feePayer = wallet.publicKey;

      const sig = await wallet.sendTransaction(tx, connection, {
        preflightCommitment: "confirmed",
      });

      await connection.confirmTransaction(sig, "confirmed");

      console.log("✅ Space created:", sig);

      onCreated?.();
      setBusy(false);
      onClose();
    } catch (e: any) {
      setBusy(false);
      setErr(String(e?.message || e));
    }
  }

  /* ---------------- UI ---------------- */

  const headerBg =
    "radial-gradient(800px 380px at 10% 0%, rgba(124,77,255,0.35), transparent 60%)," +
    "radial-gradient(700px 340px at 90% 10%, rgba(38,198,255,0.25), transparent 55%)," +
    "radial-gradient(circle at 1px 1px, rgba(255,255,255,0.08) 1px, rgba(0,0,0,0) 1.8px)," +
    "linear-gradient(180deg, rgba(10,14,26,0.96), rgba(6,8,16,0.96))";

  return (
    <Dialog
      open={open}
      onClose={busy ? undefined : onClose}
      fullWidth
      maxWidth="md"
      PaperProps={{
        sx: {
          borderRadius: 9,
          overflow: "hidden",
          border: "3px solid rgba(0,0,0,0.55)",
          boxShadow: "14px 14px 0 rgba(0,0,0,0.35)",
          background: headerBg,
          backgroundSize: "auto, auto, 14px 14px, auto",
          color: "rgba(255,255,255,0.92)",
          outline: "1px solid rgba(255,255,255,0.08)",
        },
      }}
    >
      <DialogContent sx={{ p: 0 }}>
        {/* Header */}
        <Box sx={{ px: 5, pt: 5, pb: 2 }}>
          <Stack direction="row" justifyContent="space-between" alignItems="center">
            <Box>
              <Typography variant="h3" sx={{ fontFamily: '"Bangers"' }}>
                SPACE SETUP
              </Typography>
              <Typography sx={{ opacity: 0.8 }}>
                Create the per-DAO Space PDA
              </Typography>
            </Box>
            <Stack direction="row" spacing={1}>
              <Chip
                label={
                  wallet.publicKey
                    ? `WALLET: ${wallet.publicKey
                        .toBase58()
                        .slice(0, 4)}…${wallet.publicKey
                        .toBase58()
                        .slice(-4)}`
                    : "Wallet: not connected"
                }
              />
              <Button onClick={onClose} disabled={busy}>
                <CloseIcon />
              </Button>
            </Stack>
          </Stack>
        </Box>

        <Divider />

        {/* Body */}
        <Box sx={{ px: 5, py: 4 }}>
          <Paper sx={{ p: 4 }}>
            <Stack spacing={2}>
              <Box>
                <Typography>DAO ID</Typography>
                <Box sx={{ fontFamily: "monospace" }}>
                  {daoIdStr || "—"}
                </Box>
              </Box>

              <Box>
                <Typography>Derived Space PDA</Typography>
                <Stack direction="row" spacing={1}>
                  <Box sx={{ fontFamily: "monospace", flex: 1 }}>
                    {spacePda?.toBase58() || "—"}
                  </Box>
                  <Button onClick={() => copy(spacePda?.toBase58() || "")}>
                    <ContentCopyIcon fontSize="small" />
                  </Button>
                </Stack>
              </Box>

              <Box>
                <Typography>Salt (32 bytes)</Typography>
                <Box sx={{ fontFamily: "monospace" }}>
                  {bytesToHex(salt)}
                </Box>
                <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
                  <Button
                    startIcon={<AutoAwesomeIcon />}
                    onClick={() => setSalt(randomSalt32())}
                    disabled={busy}
                  >
                    Generate
                  </Button>
                  <Button
                    startIcon={<ContentCopyIcon />}
                    onClick={() => copy(bytesToHex(salt))}
                    disabled={!salt || busy}
                  >
                    Copy
                  </Button>
                </Stack>
              </Box>

              {err && (
                <Paper sx={{ p: 1, background: "rgba(255,0,0,0.1)" }}>
                  <Typography sx={{ fontSize: 12 }}>{err}</Typography>
                </Paper>
              )}

              <Divider />

              <Stack direction="row" spacing={1}>
                <Button
                  variant="contained"
                  onClick={handleCreate}
                  disabled={busy || !wallet.publicKey || !daoPk}
                >
                  {busy ? "Creating…" : "Create Space"}
                </Button>
                <Button variant="outlined" onClick={onClose} disabled={busy}>
                  Cancel
                </Button>
              </Stack>
            </Stack>
          </Paper>
        </Box>
      </DialogContent>
    </Dialog>
  );
}