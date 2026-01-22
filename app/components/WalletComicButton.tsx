"use client";

import React, { useEffect, useMemo, useState } from "react";
import { Button, Menu, MenuItem, Stack, Typography } from "@mui/material";
import AccountBalanceWalletIcon from "@mui/icons-material/AccountBalanceWallet";
import LogoutIcon from "@mui/icons-material/Logout";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";

import { useWallet } from "@solana/wallet-adapter-react";
import { useWalletModal } from "@solana/wallet-adapter-react-ui";

function short(pk: string) {
  return pk.slice(0, 4) + "…" + pk.slice(-4);
}

export default function WalletComicButton() {
  const { publicKey, connected, disconnect } = useWallet();
  const { setVisible } = useWalletModal();

  // ✅ prevents SSR/client mismatch
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const walletBase58 = useMemo(() => publicKey?.toBase58() || "", [publicKey]);

  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const menuOpen = Boolean(anchorEl);

  function openMenu(e: React.MouseEvent<HTMLElement>) {
    setAnchorEl(e.currentTarget);
  }
  function closeMenu() {
    setAnchorEl(null);
  }

  async function copyAddr() {
    try {
      await navigator.clipboard.writeText(walletBase58);
    } catch {}
    closeMenu();
  }

  async function doDisconnect() {
    try {
      await disconnect();
    } catch {}
    closeMenu();
  }

  if (!mounted) {
    // render nothing on server + first paint; avoids hydration mismatch
    return null;
  }

  if (!connected || !publicKey) {
    return (
      <Button
        onClick={() => setVisible(true)}
        startIcon={<AccountBalanceWalletIcon />}
        sx={{
          borderRadius: 999,
          px: 2.25,
          py: 1.1,
          fontFamily: '"Bangers", system-ui',
          letterSpacing: 0.8,
          border: "3px solid #0b1220",
          boxShadow: "4px 4px 0 #0b1220",
          background: "linear-gradient(180deg, rgba(124,77,255,0.35), rgba(38,198,255,0.25))",
          color: "rgba(255,255,255,0.92)",
          "&:hover": { background: "linear-gradient(180deg, rgba(124,77,255,0.45), rgba(38,198,255,0.32))" },
        }}
      >
        Select Wallet
      </Button>
    );
  }

  return (
    <>
      <Button
        onClick={openMenu}
        sx={{
          borderRadius: 10,
          px: 2.25,
          py: 1.05,
          fontFamily: '"Bangers", system-ui',
          letterSpacing: 0.8,
          border: "3px solid #0b1220",
          boxShadow: "4px 4px 0 #0b1220",
          background: "rgba(124,77,255,0.30)",
          color: "rgba(255,255,255,0.92)",
          "&:hover": { background: "rgba(124,77,255,0.38)" },
        }}
      >
        <Stack direction="row" spacing={1} alignItems="center">
          <Typography sx={{ fontFamily: '"Bangers", system-ui' }}>
            {short(walletBase58)}
          </Typography>
        </Stack>
      </Button>

      <Menu
        anchorEl={anchorEl}
        open={menuOpen}
        onClose={closeMenu}
        PaperProps={{
          sx: {
            mt: 1,
            borderRadius: 3,
            border: "3px solid #0b1220",
            boxShadow: "6px 6px 0 #0b1220",
            background: "rgba(10,14,26,0.98)",
            color: "rgba(255,255,255,0.92)",
            overflow: "hidden",
            minWidth: 220,
          },
        }}
      >
        <MenuItem onClick={copyAddr}>
          <ContentCopyIcon fontSize="small" style={{ marginRight: 10 }} />
          Copy address
        </MenuItem>

        <MenuItem onClick={doDisconnect}>
          <LogoutIcon fontSize="small" style={{ marginRight: 10 }} />
          Disconnect
        </MenuItem>
      </Menu>
    </>
  );
}