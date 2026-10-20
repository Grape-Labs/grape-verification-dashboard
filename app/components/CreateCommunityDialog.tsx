"use client";

import React, { useEffect, useMemo, useState } from "react";
import {
  Box,
  Button,
  Dialog,
  DialogContent,
  Divider,
  Alert,
  TextField,
  Stepper,
  Step,
  StepLabel,
  CircularProgress,
  Paper,
  Stack,
  Typography,
} from "@mui/material";
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";
import WalletComicButton from "./WalletComicButton";
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
  onConfigure?: () => void;
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

export default function CreateCommunityDialog({ open, onClose, onCreated, onConfigure }: Props) {
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
  const [step, setStep] = useState(0);
  const [created, setCreated] = useState(false);
  const [progress, setProgress] = useState("");

  const daoPk = useMemo(() => safePk(daoIdInput), [daoIdInput]);

  useEffect(() => {
    if (!open) {
      setBusy(false);
      setErr("");
      return;
    }

    setErr("");
    setBusy(false);
    setStep(0);
    setCreated(false);
    setProgress("");
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
    setProgress("Preparing your community…");
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

      setProgress("Confirm the request in your wallet…");
      const sig = await wallet.sendTransaction(tx, connection, {
        preflightCommitment: "confirmed",
      });

      setProgress("Creating your community on Solana…");
      const confirmation = await connection.confirmTransaction(
        { signature: sig, blockhash, lastValidBlockHeight },
        "confirmed"
      );

      if (confirmation.value.err) throw new Error("The transaction failed. Your community was not created. Please try again.");
      setCreated(true);
      onCreated?.({
        daoId: daoPk.toBase58(),
        name: trimmedName,
        slug: trimmedSlug || undefined,
        guildId: trimmedGuild || undefined,
        attestor: configuredAttestor
          ? configuredAttestor.toBase58()
          : wallet.publicKey.toBase58(),
      });

    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      setErr(message);
    } finally {
      setBusy(false);
    }
  }

  const nameBytes = new TextEncoder().encode(JSON.stringify({ name: communityName.trim(), ...(slug.trim() ? { slug: slug.trim() } : {}), ...(guildId.trim() ? { guildId: guildId.trim() } : {}) })).length;
  const nameTooLong = nameBytes > COMMUNITY_METADATA_MAX_LEN;
  const serviceInvalid = !!attestorInput.trim() && !safePk(attestorInput);
  const canContinue = !!communityName.trim() && !nameTooLong;

  return (
    <Dialog open={open} onClose={busy ? undefined : onClose} fullWidth maxWidth="sm" aria-labelledby="create-community-title"
      PaperProps={{ sx: { borderRadius: 4, border: "2px solid rgba(124,77,255,.35)",
        background: "radial-gradient(ellipse at top left, rgba(124,77,255,.22), transparent 65%), #111625",
        boxShadow: "0 24px 80px rgba(0,0,0,.5)" } }}>
      <Box sx={{ p: { xs: 2.5, sm: 3.5 }, pb: 2 }}>
        <Stack direction="row" alignItems="flex-start" justifyContent="space-between" spacing={1}>
          <Box>
            <Typography sx={{ fontSize: 11, fontWeight: 700, letterSpacing: 2, color: "#b9a4ff", mb: 1 }}>COMMUNITY SETUP</Typography>
            <Typography id="create-community-title" variant="h3">{created ? "Your community is created!" : step === 0 ? "Start your community" : "Ready to create?"}</Typography>
            <Typography variant="body2" sx={{ color: "text.secondary", mt: 1 }}>
              {created ? "One more step before inviting members." : step === 0 ? "Give your members a place to verify their wallets." : "Review the details, then approve one transaction."}
            </Typography>
          </Box>
          <Button onClick={onClose} disabled={busy} aria-label="Close community setup" sx={{ minWidth: 40, p: 1 }}><CloseIcon /></Button>
        </Stack>
        {!created && <Stepper activeStep={step} sx={{ mt: 3, '& .MuiStepLabel-label': { fontFamily: "system-ui", fontSize: 13 } }}>
          <Step><StepLabel>Name</StepLabel></Step><Step><StepLabel>Review & create</StepLabel></Step>
        </Stepper>}
      </Box>
      <Divider />
      <DialogContent sx={{ p: { xs: 2.5, sm: 3.5 } }}>
        {created ? <Stack spacing={2.5}>
          <Box sx={{ p: 2.5, borderRadius: 3, background: "rgba(74,222,128,.08)", border: "1px solid rgba(74,222,128,.3)" }}>
            <CheckCircleOutlineIcon sx={{ color: "#86efac", fontSize: 40, mb: 1 }} />
            <Typography variant="h5" sx={{ overflowWrap: "anywhere" }}>{communityName.trim()}</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: "text.secondary" }}>Your community is saved. Your wallet is its administrator.</Typography>
          </Box>
          <Box>
            <Typography fontWeight={700}>Next: enable member verification</Typography>
            <Typography variant="body2" sx={{ mt: 0.75, color: "text.secondary" }}>Configure and check your verification service before sharing your community with members.</Typography>
          </Box>
          <Button variant="contained" size="large" onClick={() => { onClose(); onConfigure?.(); }}>Set up verification</Button>
          <Button onClick={onClose}>I’ll do this later</Button>
        </Stack> : <Stack spacing={2.5}>
          {step === 0 ? <>
            <TextField autoFocus fullWidth label="Community name" placeholder="e.g. Grape DAO" value={communityName}
              onChange={event => setCommunityName(event.target.value)} error={nameTooLong}
              helperText={nameTooLong ? "Please shorten the name or optional details." : "The name members will see when verifying."}
              onKeyDown={event => { if (event.key === "Enter" && canContinue) { event.preventDefault(); setStep(1); } }} />
            <Paper variant="outlined" sx={{ p: 2, background: "rgba(124,77,255,.07)" }}>
              <Typography variant="body2">We’ll create your community ID automatically. You can add Discord details later.</Typography>
            </Paper>
          </> : <>
            <Box sx={{ p: 2.5, borderRadius: 3, background: "rgba(124,77,255,.10)", border: "1px solid rgba(124,77,255,.25)" }}>
              <Typography variant="caption" color="text.secondary">YOUR COMMUNITY</Typography>
              <Typography variant="h5" sx={{ mt: 0.5, overflowWrap: "anywhere" }}>{communityName.trim()}</Typography>
            </Box>
            <Box>
              <Typography fontWeight={700} sx={{ mb: 1 }}>Administrator wallet</Typography>
              {busy ? <Typography variant="body2">{wallet.publicKey?.toBase58()}</Typography> : <WalletComicButton />}
              <Typography variant="body2" sx={{ mt: 1, color: "text.secondary" }}>{wallet.publicKey ? "This wallet will manage your community and approve setup changes." : "Connect the wallet you want to manage this community."}</Typography>
            </Box>
            <Typography variant="body2" color="text.secondary">You’ll approve a Solana transaction. Your wallet needs SOL for network fees and account storage.</Typography>
            <Alert severity="info">After creation, we’ll take you to verification setup so members can start joining.</Alert>
            <Box component="details" sx={{ '& summary': { cursor: 'pointer', fontFamily: 'system-ui', fontSize: 13, color: '#b9a4ff' } }}>
              <summary>Advanced configuration</summary>
              <Stack spacing={2} sx={{ mt: 2 }}>
                <Typography variant="body2" color="text.secondary">Leave these unchanged unless you already have an integration or verification service.</Typography>
                <TextField disabled={busy} label="Short name (optional)" value={slug} onChange={e => setSlug(e.target.value.toLowerCase().replace(/\s+/g, "-"))} />
                <TextField disabled={busy} label="Discord server ID (optional)" value={guildId} onChange={e => setGuildId(e.target.value)} helperText="Adds a server reference; it does not install a bot." />
                <TextField disabled={busy} label="Verification service wallet (optional)" value={attestorInput} onChange={e => setAttestorInput(e.target.value)} error={serviceInvalid}
                  helperText={serviceInvalid ? "Enter a valid Solana public address." : "Public address only. If blank, your administrator wallet is used until you configure a service."} />
                <TextField disabled={busy} label="Community ID" value={daoIdInput} onChange={e => setDaoIdInput(e.target.value)} error={!daoPk} helperText="Generated automatically. Change only to use an existing DAO address." />
              </Stack>
            </Box>
          </>}
          {err && <Alert severity="error">{err}</Alert>}
          {nameTooLong && step === 1 && <Alert severity="error">Please shorten the name or optional details before creating.</Alert>}
          {busy && <Stack direction="row" spacing={1.5} alignItems="center" role="status"><CircularProgress size={18} /><Typography variant="body2">{progress}</Typography></Stack>}
          <Stack direction="row" spacing={1.5}>
            {step === 1 && <Button disabled={busy} onClick={() => { setStep(0); setErr(""); }}>Back</Button>}
            <Button variant="contained" size="large" fullWidth disabled={busy || !canContinue || (step === 1 && (!wallet.publicKey || !daoPk || serviceInvalid))}
              onClick={() => step === 0 ? setStep(1) : handleCreateCommunity()}>
              {busy ? "Creating…" : step === 0 ? "Continue" : "Create community"}
            </Button>
          </Stack>
        </Stack>}
      </DialogContent>
    </Dialog>
  );
}
