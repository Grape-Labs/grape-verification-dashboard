"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { ConnectionProvider, WalletProvider } from "@solana/wallet-adapter-react";
import { WalletModalProvider } from "@solana/wallet-adapter-react-ui";
import { PhantomWalletAdapter, SolflareWalletAdapter } from "@solana/wallet-adapter-wallets";

import { CssBaseline, ThemeProvider } from "@mui/material";
import { theme } from "./theme";

import "@solana/wallet-adapter-react-ui/styles.css";
import "@fontsource/bangers/400.css";
import "@fontsource/roboto-mono/400.css";

const RPC_STORAGE_KEY = "gvd_solana_rpc";

type RpcSettings = {
  endpoint: string;
  defaultEndpoint: string;
  customEndpoint: string | null;
  setCustomEndpoint: (endpoint: string) => void;
  resetEndpoint: () => void;
};

const RpcSettingsContext = createContext<RpcSettings | null>(null);

export function useRpcSettings(): RpcSettings {
  const value = useContext(RpcSettingsContext);
  if (!value) throw new Error("useRpcSettings must be used inside Providers");
  return value;
}

export default function Providers({ children }: { children: React.ReactNode }) {
  const defaultEndpoint =
    process.env.NEXT_PUBLIC_SOLANA_RPC || "https://api.devnet.solana.com";
  const [customEndpoint, setCustomEndpointState] = useState<string | null>(null);

  useEffect(() => {
    try {
      const saved = window.localStorage.getItem(RPC_STORAGE_KEY)?.trim();
      if (saved) setCustomEndpointState(saved);
    } catch {
      // Browser storage may be unavailable in privacy-restricted contexts.
    }
  }, []);

  const setCustomEndpoint = useCallback((endpoint: string) => {
    const normalized = endpoint.trim();
    window.localStorage.setItem(RPC_STORAGE_KEY, normalized);
    setCustomEndpointState(normalized);
  }, []);

  const resetEndpoint = useCallback(() => {
    try {
      window.localStorage.removeItem(RPC_STORAGE_KEY);
    } finally {
      setCustomEndpointState(null);
    }
  }, []);

  const endpoint = customEndpoint || defaultEndpoint;
  const rpcSettings = useMemo(
    () => ({
      endpoint,
      defaultEndpoint,
      customEndpoint,
      setCustomEndpoint,
      resetEndpoint,
    }),
    [endpoint, defaultEndpoint, customEndpoint, setCustomEndpoint, resetEndpoint]
  );

  const wallets = useMemo(() => [new PhantomWalletAdapter(), new SolflareWalletAdapter()], []);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <RpcSettingsContext.Provider value={rpcSettings}>
        <ConnectionProvider endpoint={endpoint}>
          <WalletProvider wallets={wallets} autoConnect>
            <WalletModalProvider>{children}</WalletModalProvider>
          </WalletProvider>
        </ConnectionProvider>
      </RpcSettingsContext.Provider>
    </ThemeProvider>
  );
}
