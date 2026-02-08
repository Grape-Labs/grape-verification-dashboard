// components/TelegramLoginButton.tsx
"use client";

import { useEffect, useRef } from "react";
import { Button, Box } from "@mui/material";

interface TelegramUser {
  id: number;
  first_name: string;
  last_name?: string;
  username?: string;
  photo_url?: string;
  auth_date: number;
  hash: string;
}

export default function TelegramLoginButton({
  onAuth,
  botUsername,
}: {
  onAuth: (user: TelegramUser) => void;
  botUsername: string;
}) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Define callback globally
    (window as any).onTelegramAuth = (user: TelegramUser) => {
      console.log("Telegram auth callback:", user);
      onAuth(user);
    };

    // Load Telegram widget script
    const script = document.createElement("script");
    script.src = "https://telegram.org/js/telegram-widget.js?22";
    script.async = true;
    script.setAttribute("data-telegram-login", botUsername);
    script.setAttribute("data-size", "large");
    script.setAttribute("data-onauth", "onTelegramAuth(user)");
    script.setAttribute("data-request-access", "write");

    if (containerRef.current) {
      containerRef.current.appendChild(script);
    }

    return () => {
      delete (window as any).onTelegramAuth;
      if (script.parentNode) {
        script.parentNode.removeChild(script);
      }
    };
  }, [botUsername, onAuth]);

  return <Box ref={containerRef} sx={{ display: "inline-block" }} />;
}