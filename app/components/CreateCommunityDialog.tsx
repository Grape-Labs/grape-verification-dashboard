"use client";

import React, { useEffect, useMemo, useState } from "react";
import {
  Box,
  Button,
  Dialog,
  DialogContent,
  Divider,
  Paper,
  Stack,
  Typography,
} from "@mui/material";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import CloseIcon from "@mui/icons-material/Close";

import { useConnection, useWallet } from "@solana/wallet-adapter-react";
import { Keypair, PublicKey, Transaction, TransactionInstruction } from "@solana/web3.js";
import { Buffer } from "buffer";
import { sha256 } from "@noble/hashes/sha256";
import { utf8ToBytes } from "@noble/hashes/utils";

import {
  buildInitializeSpaceIx,
  buildSetSpaceCommunityMetadataIx,
  COMMUNITY_METADATA_MAX_LEN,
  deriveSpacePda,
  PROGRAM_ID,
} from "@grapenpm/grape-verification-registry";

type Props = {
  open: boolean;
  onClose: () => void;
  onCreated?: (result: {
    daoId: string;
    name?: string;
    slug?: string;
    guildId?: string;
    attestor?: string;
  }) => void;
};

function randomSalt32(): Uint8Array {
  const u8 = new Uint8Array(32);
  crypto.getRandomValues(u8);
  return u8;
}

function randomDaoId(): string {
  return Keypair.generate().publicKey.toBase58();
}

function safePk(value: string): PublicKey | null {
  try {
    return new PublicKey(value.trim());
  } catch {
    return null;
  }
}

function concatBytes(...arrays: Uint8Array[]) {
  const len = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function ixDisc(nameSnake: string): Uint8Array {
  return sha256(utf8ToBytes(`global:${nameSnake}`)).slice(0, 8);
}

function buildSetSpaceAttestorIx(args: {
  daoId: PublicKey;
  authority: PublicKey;
  newAttestor: PublicKey;
  programId?: PublicKey;
}) {
  const programId = args.programId ?? PROGRAM_ID;
  const disc = ixDisc("set_space_attestor");
  const [spaceAcct] = deriveSpacePda(args.daoId);
  const data = Buffer.from(
    concatBytes(disc, args.daoId.toBytes(), args.newAttestor.toBytes())
  );

  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: spaceAcct, isSigner: false, isWritable: true },
      { pubkey: args.authority, isSigner: true, isWritable: false },
    ],
    data,
  });
}

export default function CreateCommunityDialog({ open, onClose, onCreated }: Props) {
  const { connection } = useConnection();
  const wallet = useWallet();

  const [communityName, setCommunityName] = useState("");
  const [slug, setSlug] = useState("");
  const [guildId, setGuildId] = useState("");
  const [daoIdInput, setDaoIdInput] = useState("");
  const [attestorInput, setAttestorInput] = useState("");
  const [salt, setSalt] = useState<Uint8Array | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const daoPk = useMemo(() => safePk(daoIdInput), [daoIdInput]);
  const spacePda = useMemo(() => {
    if (!daoPk) return null;
    const [pda] = deriveSpacePda(daoPk);
    return pda;
  }, [daoPk]);

  useEffect(() => {
    if (!open) {
      setBusy(false);
      setErr("");
      return;
    }

    setErr("");
    setBusy(false);
    setCommunityName("");
    setSlug("");
    setGuildId("");
    setAttestorInput(
      (process.env.NEXT_PUBLIC_ATTESTOR_PUBKEY || "").trim()
    );
    setDaoIdInput(randomDaoId());
    setSalt(randomSalt32());
  }, [open]);

  async function handleCreateCommunity() {
    setErr("");
    setBusy(true);
    try {
      if (!wallet.publicKey) throw new Error("Connect a wallet first.");
      if (!wallet.sendTransaction)
        throw new Error("Wallet adapter missing sendTransaction.");
      if (!daoPk) throw new Error("DAO ID is invalid.");

      const trimmedName = communityName.trim();
      if (!trimmedName) throw new Error("Community name is required.");

      const trimmedSlug = slug.trim();
      const trimmedGuild = guildId.trim();
      const trimmedAttestor = attestorInput.trim();
      const configuredAttestor = trimmedAttestor ? safePk(trimmedAttestor) : null;
      if (trimmedAttestor && !configuredAttestor) {
        throw new Error("Attestor public key is invalid.");
      }

      const metadata: Record<string, string> = { name: trimmedName };
      if (trimmedSlug) metadata.slug = trimmedSlug;
      if (trimmedGuild) metadata.guildId = trimmedGuild;

      const metadataValue = JSON.stringify(metadata);
      const metadataBytes = new TextEncoder().encode(metadataValue);
      if (metadataBytes.length > COMMUNITY_METADATA_MAX_LEN) {
        throw new Error(
          `Metadata is too long (${metadataBytes.length}/${COMMUNITY_METADATA_MAX_LEN} bytes).`
        );
      }

      const saltBytes = salt ?? randomSalt32();
      setSalt(saltBytes);

      const tx = new Transaction();
      const initIx = buildInitializeSpaceIx({
        daoId: daoPk,
        salt: saltBytes,
        authority: wallet.publicKey,
        payer: wallet.publicKey,
        programId: PROGRAM_ID,
      }).ix;
      tx.add(initIx);

      if (
        configuredAttestor &&
        !configuredAttestor.equals(wallet.publicKey)
      ) {
        tx.add(
          buildSetSpaceAttestorIx({
            daoId: daoPk,
            authority: wallet.publicKey,
            newAttestor: configuredAttestor,
            programId: PROGRAM_ID,
          })
        );
      }

      const metaIx = buildSetSpaceCommunityMetadataIx({
        daoId: daoPk,
        authority: wallet.publicKey,
        payer: wallet.publicKey,
        communityMetadata: metadataValue,
        programId: PROGRAM_ID,
      }).ix;
      tx.add(metaIx);

      tx.feePayer = wallet.publicKey;
      const { blockhash, lastValidBlockHeight } =
        await connection.getLatestBlockhash("confirmed");
      tx.recentBlockhash = blockhash;

      const sig = await wallet.sendTransaction(tx, connection, {
        preflightCommitment: "confirmed",
      });

      await connection.confirmTransaction(
        { signature: sig, blockhash, lastValidBlockHeight },
        "confirmed"
      );

      onCreated?.({
        daoId: daoPk.toBase58(),
        name: trimmedName,
        slug: trimmedSlug || undefined,
        guildId: trimmedGuild || undefined,
        attestor: configuredAttestor
          ? configuredAttestor.toBase58()
          : wallet.publicKey.toBase58(),
      });
      onClose();
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      setErr(message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={open}
      onClose={busy ? undefined : onClose}
      fullWidth
      maxWidth="md"
      PaperProps={{
        sx: {
          borderRadius: 2,
          overflow: "hidden",
          border: "3px solid rgba(0,0,0,0.55)",
          boxShadow: "14px 14px 0 rgba(0,0,0,0.35)",
          background:
            "radial-gradient(800px 380px at 10% 0%, rgba(124,77,255,0.35), transparent 60%)," +
            "radial-gradient(700px 340px at 90% 10%, rgba(38,198,255,0.25), transparent 55%)," +
            "radial-gradient(circle at 1px 1px, rgba(255,255,255,0.08) 1px, rgba(0,0,0,0) 1.8px)," +
            "linear-gradient(180deg, rgba(10,14,26,0.96), rgba(6,8,16,0.96))",
          backgroundSize: "auto, auto, 14px 14px, auto",
          color: "rgba(255,255,255,0.92)",
        },
      }}
    >
      <DialogContent sx={{ p: 0 }}>
        <Box sx={{ px: 4, pt: 4, pb: 2 }}>
          <Stack direction="row" justifyContent="space-between" alignItems="center">
            <Box>
              <Typography variant="h3" sx={{ fontFamily: '"Bangers"' }}>
                CREATE COMMUNITY
              </Typography>
              <Typography sx={{ opacity: 0.82, fontFamily: "system-ui", fontSize: 13 }}>
                Set up a new on-chain community space with metadata in one transaction.
              </Typography>
            </Box>
            <Button onClick={onClose} disabled={busy}>
              <CloseIcon />
            </Button>
          </Stack>
        </Box>

        <Divider />

        <Box sx={{ px: 4, py: 3 }}>
          <Paper sx={{ p: 2 }}>
            <Stack spacing={1.25}>
              <Typography sx={{ fontFamily: "system-ui", fontSize: 12, fontWeight: 700 }}>
                Community Name
              </Typography>
              <Box
                component="input"
                value={communityName}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setCommunityName(e.target.value)
                }
                placeholder="e.g. Grape DAO"
                style={{
                  width: "100%",
                  padding: "10px 12px",
                  borderRadius: 10,
                  border: "2px solid rgba(255,255,255,0.18)",
                  outline: "none",
                  fontFamily: "system-ui",
                  background: "rgba(255,255,255,0.08)",
                  color: "rgba(255,255,255,0.92)",
                }}
              />

              <Typography sx={{ fontFamily: "system-ui", fontSize: 12, fontWeight: 700 }}>
                Slug (optional)
              </Typography>
              <Box
                component="input"
                value={slug}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setSlug(e.target.value.toLowerCase().replace(/\s+/g, "-"))
                }
                placeholder="e.g. grape"
                style={{
                  width: "100%",
                  padding: "10px 12px",
                  borderRadius: 10,
                  border: "2px solid rgba(255,255,255,0.18)",
                  outline: "none",
                  fontFamily: "system-ui",
                  background: "rgba(255,255,255,0.08)",
                  color: "rgba(255,255,255,0.92)",
                }}
              />

              <Typography sx={{ fontFamily: "system-ui", fontSize: 12, fontWeight: 700 }}>
                Discord Guild ID (optional)
              </Typography>
              <Box
                component="input"
                value={guildId}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setGuildId(e.target.value)
                }
                placeholder="e.g. 837189238289203201"
                style={{
                  width: "100%",
                  padding: "10px 12px",
                  borderRadius: 10,
                  border: "2px solid rgba(255,255,255,0.18)",
                  outline: "none",
                  fontFamily: "system-ui",
                  background: "rgba(255,255,255,0.08)",
                  color: "rgba(255,255,255,0.92)",
                }}
              />

              <Typography sx={{ fontFamily: "system-ui", fontSize: 12, fontWeight: 700 }}>
                Attestor Wallet (optional)
              </Typography>
              <Box
                component="input"
                value={attestorInput}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setAttestorInput(e.target.value)
                }
                placeholder="Defaults to connected authority wallet"
                style={{
                  width: "100%",
                  padding: "10px 12px",
                  borderRadius: 10,
                  border: "2px solid rgba(255,255,255,0.18)",
                  outline: "none",
                  fontFamily: "monospace",
                  background: "rgba(255,255,255,0.08)",
                  color: "rgba(255,255,255,0.92)",
                }}
              />

              <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
                <Box sx={{ flex: 1 }}>
                  <Typography sx={{ fontFamily: "system-ui", fontSize: 12, fontWeight: 700 }}>
                    DAO ID
                  </Typography>
                  <Box
                    component="input"
                    value={daoIdInput}
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                      setDaoIdInput(e.target.value)
                    }
                    placeholder="DAO public key"
                    style={{
                      width: "100%",
                      padding: "10px 12px",
                      borderRadius: 10,
                      border: "2px solid rgba(255,255,255,0.18)",
                      outline: "none",
                      fontFamily: "monospace",
                      background: "rgba(255,255,255,0.08)",
                      color: "rgba(255,255,255,0.92)",
                    }}
                  />
                </Box>
                <Stack justifyContent="flex-end">
                  <Button
                    startIcon={<AutoAwesomeIcon />}
                    variant="outlined"
                    onClick={() => setDaoIdInput(randomDaoId())}
                    disabled={busy}
                    sx={{ fontFamily: '"Bangers", system-ui', letterSpacing: 0.6 }}
                  >
                    Generate DAO ID
                  </Button>
                </Stack>
              </Stack>

              <Typography sx={{ fontFamily: "system-ui", fontSize: 11, opacity: 0.74 }}>
                {`Derived Space PDA: ${spacePda?.toBase58() || "—"}`}
              </Typography>

              {!wallet.publicKey && (
                <Typography sx={{ fontFamily: "system-ui", fontSize: 12, opacity: 0.8 }}>
                  Connect a wallet to create this community.
                </Typography>
              )}

              {err && (
                <Paper sx={{ p: 1, background: "rgba(255,0,0,0.12)" }}>
                  <Typography sx={{ fontFamily: "system-ui", fontSize: 12 }}>
                    {err}
                  </Typography>
                </Paper>
              )}

              <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
                <Button
                  variant="contained"
                  onClick={handleCreateCommunity}
                  disabled={busy || !wallet.publicKey || !daoPk || !communityName.trim()}
                  sx={{ fontFamily: '"Bangers", system-ui', letterSpacing: 0.7 }}
                >
                  {busy ? "Creating..." : "Create Community"}
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
