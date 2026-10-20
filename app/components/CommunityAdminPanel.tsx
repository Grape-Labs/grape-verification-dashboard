"use client";

import { useEffect, useState } from "react";
import { Alert, Box, Button, Paper, Stack, Typography, Table, TableBody, TableCell, TableContainer, TableHead, TableRow } from "@mui/material";
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
    {stats && <>
      <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", sm: "repeat(3, 1fr)" }, gap: 2, my: 3 }}>
        {[
          ["Active identities", stats.activeIdentities],
          ["Expired identities", stats.expired],
          ["Revoked / unverified identities", stats.revoked],
          ["Identities expiring within 7 days", stats.expiringSoon],
          ["Wallets without active verification", stats.unverifiedWallets],
          ["Identities without linked wallets", stats.identitiesWithoutWallets],
        ].map(([label, count]) => <Box key={label} sx={{ p: 2, border: "1px solid", borderColor: "divider", borderRadius: 2 }}>
          <Typography variant="h5">{count}</Typography><Typography variant="body2">{label}</Typography>
        </Box>)}
      </Box>
      <Typography variant="h6">Verification methods</Typography>
      <TableContainer>
        <Table size="small" aria-label="Verification method breakdown">
          <TableHead><TableRow>
            <TableCell>Method</TableCell><TableCell align="right">Identity records</TableCell>
            <TableCell align="right">Active identities</TableCell><TableCell align="right">Verified wallets</TableCell>
          </TableRow></TableHead>
          <TableBody>{stats.methods.map(method => <TableRow key={method.platform}>
            <TableCell component="th" scope="row">{method.platform}</TableCell>
            <TableCell align="right">{method.identities}</TableCell><TableCell align="right">{method.active}</TableCell>
            <TableCell align="right">{method.wallets}</TableCell>
          </TableRow>)}</TableBody>
        </Table>
      </TableContainer>
      <Typography variant="body2" sx={{ mt: 1, mb: 3, opacity: 0.75 }}>A wallet can appear under multiple methods. Expired counts exclude revoked identities. These counts describe current records, not historical activity or unique people.</Typography>
    </>}
    <Typography variant="body2">Linked wallets are distinct wallets with an identity link in this community. Verified wallets have at least one verified, unexpired identity. Each wallet is counted once, even with multiple methods. Counts include existing records when the community is paused.</Typography>
    {stats && <Typography variant="caption">Updated {new Date(stats.checkedAt).toLocaleString()}</Typography>}
  </Paper>;
}
