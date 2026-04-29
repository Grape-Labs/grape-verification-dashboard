import React, { FC, useCallback, useMemo } from 'react';
import { useSession } from "../../contexts/session";

import {
  Grid,
  Paper,
  Box,
  Typography,
  Button,
  Chip,
  Stack
} from '@mui/material';
import { useWallet } from '@solana/wallet-adapter-react';

import { ServersView, SettingsView, WalletView } from "../";

function ConnectedWalletComponent(props) {
  return (
    <React.Fragment>
      <WalletView /> 
      <ServersView /> 
      <SettingsView />
    </React.Fragment>
  );
}

function VerificationStatusCard({ eyebrow, title, description, actionLabel, onAction, highlights = [], secondaryText = null }) {
  return (
    <Grid item xs={12}>
      <Paper className="grape-paper-background">
        <Box
          className="grape-paper verification-hero"
          sx={{
            position: 'relative',
            px: { xs: 3, md: 4 },
            py: { xs: 4, md: 5 },
          }}
        >
          <Stack direction="row" spacing={1} sx={{ mb: 2, flexWrap: 'wrap' }}>
            <Chip label={eyebrow} sx={{ background: 'rgba(241, 201, 107, 0.12)', color: 'primary.light', fontWeight: 700 }} />
            {highlights.map((item) => (
              <Chip key={item} label={item} variant="outlined" sx={{ borderColor: 'rgba(255,255,255,0.12)', color: 'text.secondary' }} />
            ))}
          </Stack>

          <Typography variant="h3" sx={{ maxWidth: 680, mb: 1.5 }}>
            {title}
          </Typography>
          <Typography variant="body1" sx={{ color: 'text.secondary', maxWidth: 720, mb: 3, fontSize: '1.02rem' }}>
            {description}
          </Typography>

          {actionLabel && onAction ? (
            <Button variant="contained" color="primary" onClick={onAction}>
              {actionLabel}
            </Button>
          ) : null}

          {secondaryText ? (
            <Typography variant="caption" sx={{ display: 'block', color: 'text.secondary', mt: 2 }}>
              {secondaryText}
            </Typography>
          ) : null}
        </Box>
      </Paper>
    </Grid>
  );
}

function BasicComponent(props) {
  const { publicKey, wallet, disconnect, connect } = useWallet();
  //const publicKey = props.publicKey;
  const { session, setSession } = useSession();
  //const setSession = props.setSession;
  //const session = props.session;
  const isConnected = session && session.isConnected;
  const isWallet = session && session.isWallet;

  const handleWalletAuthClick = (event) => {
    setSession(null);
    //session.disconnect();
    disconnect();
    const timeout = setTimeout(() => {
      connect().catch(() => {
        // Silently catch because any errors are caught by the context `onError` handler
      });
    }, 2000); // added a small delay
  };

  return (
    <React.Fragment>
      {!wallet && (
        <VerificationStatusCard
          eyebrow="Verification portal"
          title="Connect a Solana wallet to start verification."
          description="Use the wallet button in the header to sign in, verify ownership, and unlock your linked communities."
          highlights={['Wallet proof', 'Discord linking', 'Server access']}
          secondaryText="Message signing is preferred. If a wallet cannot expose it, Grape can fall back to a self-verification transaction."
        />
      )}

      {wallet && !isConnected && (
        <VerificationStatusCard
          eyebrow="Pending proof"
          title="Finish wallet verification to continue."
          description="Your wallet is connected, but the verification session is not complete yet. Reconnect and approve the prompt to finish signing."
          actionLabel="Reconnect wallet"
          onAction={handleWalletAuthClick}
          highlights={['Connected locally', 'Session not verified']}
        />
      )}

      {isConnected && !isWallet && (
        <VerificationStatusCard
          eyebrow="Limited access"
          title="Wallet detected, but proof of ownership still needs confirmation."
          description="This session is running in address-only mode. Reconnect the same wallet to retry message signing or approve the verification transaction fallback."
          actionLabel="Retry verification"
          onAction={handleWalletAuthClick}
          highlights={['Address linked', 'Proof missing']}
        />
      )}
    </React.Fragment>
  );
}

const RenderDashboardComponents = (props) => {
  const { publicKey, wallet } = useWallet();
  const session = props.session;
  //const publicKey = props.publicKey;
  const isConnected = session && session.isConnected;
  const isWallet = session && session.isWallet;
  
  //console.log("session: "+JSON.stringify(session))
  // show if connected
  //if (publicKey){
      switch(isConnected) {
        case isWallet: // display only if verified pk in wallet
          return <React.Fragment><BasicComponent /><ConnectedWalletComponent /></React.Fragment>
        default:
          return <BasicComponent />
      }
  //}
}

export const HomeView = (props) => {
  const { session, setSession } = useSession();
  const { publicKey, wallet } = useWallet();
  const [callstopk, setCallToPk] = React.useState(0);
  
  React.useEffect(() => { 
    
    setCallToPk(callstopk+1);

    //console.log(callstopk+". RENDER EFFECT SESSION CHANGED: "+session.publicKey);
    //console.log(callstopk+". RENDER EFFECT WALLET PK: "+publicKey);

    // AT THE MOMENT THE ABOVE IS NOT CHECKED - THIS WILL NEED TO BE MODIFIED TO HANDLE THE SESSION BETTER

    //if (!wallet){
    //  setSession(null);
    //}
  }, [session, publicKey]);
  
  return (
    <Grid container spacing={3}>
      <RenderDashboardComponents
        session={session} setSession={session}
      />
    </Grid>
  );
}
