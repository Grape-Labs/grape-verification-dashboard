import React, { FC, useCallback, useMemo } from 'react';
import { useSession } from "../../contexts/session";

import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import Box from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { useWallet } from '@solana/wallet-adapter-react';

import { useSnackbar } from 'notistack';
import { ServersView, SettingsView, WalletView } from "../";

function ConnectedWalletComponent(props) {
  return (
    <React.Fragment>
      <ServersView /> 
      <SettingsView />
    </React.Fragment>
  );
}

function BasicComponent(props) {
  const { publicKey, wallet } = useWallet();
  //const publicKey = props.publicKey;
  const isConnected = props.isConnected;

  return (
    <React.Fragment>
        {!isConnected &&
          <Grid 
            class="grape-paper" 
            container
            spacing={0}
            align="center"
            justify="center"
            direction="column"
            sx={{mt:4}}>
            <Grid item>
              <Typography 
                align="center"
                variant="h3">
                  not connected...
              </Typography>
            </Grid>
          </Grid>
        }
      
    </React.Fragment>
  );
}

const RenderDashboardComponents = (props) => {
  const { publicKey, wallet } = useWallet();
  const session = props.session;
  //const publicKey = props.publicKey;
  const isConnected = session && session.isConnected;
  const isWallet = session && session.isWallet;
  
  console.log("session: "+JSON.stringify(session))
  // show if connected
  //if (publicKey){
      switch(isConnected) {
        case isWallet: // display only if verified pk in wallet
          return <React.Fragment><BasicComponent isConnected={isConnected} /><ConnectedWalletComponent /></React.Fragment>
        default:
          return <BasicComponent isConnected={isConnected} />
      }
  //}
}

export const HomeView = (props) => {
  const { session, setSession } = useSession();
  const isConnected = session && session.isConnected;
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
            <>
              {wallet ? 
                <Grid container spacing={3}>
                <RenderDashboardComponents
                  session={session}
                />
              </Grid>
              :
              <Grid item xs={12}>
                <Paper class="grape-paper-background">
                  <Grid 
                    class="grape-paper" 
                    container
                    spacing={0}
                    align="center"
                    justify="center"
                    direction="column">
                    <Grid item>
                      <Typography 
                        align="center"
                        variant="h3">
                        {'Not connected'}
                      </Typography>
                    </Grid>
                  </Grid>
                </Paper>
              </Grid>}
            </>
  );
}
