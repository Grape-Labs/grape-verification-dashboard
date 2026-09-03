"use client";

import { useState } from "react";
import styles from "./page.module.css";

export default function ShareActions({ wallet }: { wallet: string }) {
  const [copied, setCopied] = useState<"address" | "link" | null>(null);

  async function copy(value: string, kind: "address" | "link") {
    await navigator.clipboard.writeText(value);
    setCopied(kind);
    window.setTimeout(() => setCopied(null), 1600);
  }

  return (
    <div className={styles.actions}>
      <button type="button" onClick={() => copy(wallet, "address")}>
        {copied === "address" ? "Address copied" : "Copy address"}
      </button>
      <button type="button" onClick={() => copy(window.location.href, "link")}>
        {copied === "link" ? "Link copied" : "Copy share link"}
      </button>
    </div>
  );
}

