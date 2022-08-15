import React, { FC, useCallback, useMemo } from 'react';
import { useSession } from "../../contexts/session";

import {
  Grid,
  Paper,
  Box,
  Typography,
  Button
} from '@mui/material';
import { useWallet } from '@solana/wallet-adapter-react';

import { useSnackbar } from 'notistack';
import { ServersView, SettingsView, WalletView } from "../";
import ConnectDialog from '../../components/ConnectDialog/ConnectDialog';

function ConnectedWalletComponent(props) {
  return (
    <React.Fragment>
      <ServersView /> 
      <SettingsView />
    </React.Fragment>
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
        {!isConnected ?
          <Grid item xs={12}>
            <Paper class="grape-paper-background">
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
                      connecting...
                  </Typography>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
          :
          <>
            {!isWallet &&
              <Grid item xs={12}>
                <Paper class="grape-paper-background">
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
                          Proof of wallet required
                      </Typography>
                      <Typography 
                        align="center"
                        variant="h3">
                          
                          <Button
                            onClick={(event) => 
                              handleWalletAuthClick(event)}
                          >Reconnect your wallet</Button>
                      </Typography>
                      
                    </Grid>
                  </Grid>
                </Paper>
              </Grid>
            }
          </>
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
                  session={session} setSession={session}
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
