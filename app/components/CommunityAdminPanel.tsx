"use client";

import { useEffect, useState } from "react";
import { Alert, Button, Paper, Stack, Typography } from "@mui/material";
import { Connection, PublicKey } from "@solana/web3.js";
import { loadCommunityStats } from "@/lib/community-stats";

export default function CommunityAdminPanel({ connection, space, community, revision }: {
  connection: Connection; space: PublicKey; community: string; revision: number;
}) {
  const [reload, setReload] = useState(0);
  const [stats, setStats] = useState<Awaited<ReturnType<typeof loadCommunityStats>> | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let cancelled = false;
    // Reset the previous RPC snapshot when the connection or refresh revision changes.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setLoading(true);
    setStats(null);
    setError("");
    loadCommunityStats(connection, space).then(value => {
      if (!cancelled) setStats(value);
    }).catch(() => {
      if (!cancelled) setError("Could not load community counts from Solana. Try refreshing.");
    }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [connection, space, revision, reload]);
  return <Paper variant="outlined" sx={{ p: 3, my: 2 }}>
    <Stack direction="row" justifyContent="space-between" alignItems="center">
      <Typography variant="h5">Community admin · {community}</Typography>
      <Button disabled={loading} onClick={() => setReload(n => n + 1)}>Refresh counts</Button>
    </Stack>
    {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
    <Stack direction={{ xs: "column", sm: "row" }} spacing={4} sx={{ my: 2 }} aria-live="polite" aria-busy={loading}>
      {[["Verified wallets", stats?.verified], ["Linked wallets", stats?.linked], ["Identity records", stats?.identities]].map(([label, count]) =>
        <div key={label}><Typography variant="h4">{loading ? "…" : count ?? "—"}</Typography><Typography>{label}</Typography></div>
      )}
    </Stack>
    <Typography variant="body2">Linked wallets are distinct wallets with an identity link in this community. Verified wallets have at least one verified, unexpired identity. Each wallet is counted once, even with multiple methods. Counts include existing records when the community is paused.</Typography>
    {stats && <Typography variant="caption">Updated {new Date(stats.checkedAt).toLocaleString()}</Typography>}
  </Paper>;
}
