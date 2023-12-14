import * as React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Typography,
  Button,
  Grid,
} from '@mui/material/';
//import OrcaSwap from '../OrcaSwap/OrcaSwap';
import { useWallet } from '@solana/wallet-adapter-react';
import { makeFtxPayUrl } from '../../utils/ftx-pay';
import JupiterSwap from "../JupiterSwap/JupiterSwap";

interface SummaryProps {
  children?: React.ReactNode;
}

export default function Summary(props: any) {
  //const theme = useTheme();
  const title = props.title;
  const subtitle = props.subtitle;
  const showtimestamp = props.showtimestamp;
  const tstamp = props.tstamp;
  const swaptoken = props.swaptoken || null;
  const swaptomint = props.swaptomint || null;
  const tokenMap = props.tokenMap || null;
  const portfolioPositions = props.portfolioPositions || null;
  const { publicKey } = useWallet();
  const token = props.token;

  const [ftxurl, setFtxUrl] = React.useState(null);

  const swapfrom = 'USDC';
  const swapto = 'GRAPE';

  const handleFTXPay = () => {
    let params = `scrollbars=no,resizable=no,status=no,location=no,toolbar=no,menubar=no,
    width=600,height=675,left=100,top=100`;
    window.open(ftxurl,'FTX Pay', params);
  }

  React.useEffect(() => {
    //if (publicKey)
    //  setFtxUrl(makeFtxPayUrl(publicKey.toBase58(), 'SOL'));
  }, [publicKey]);



  //function handleSwapDialogRequest(){
  //  return <SwapDialog />
  //}

  return (
    <React.Fragment>
      <Grid container
        spacing={2}
        justifyContent="center"
        direction="column"
        alignItems="center"
      >
        <Grid item>
        {title} <small>{subtitle}</small>
        </Grid>
        <Grid item>
          <Typography variant="h4" justifyContent="center" >
            {props.children}
          </Typography>
          {showtimestamp &&
            <Typography color="text.secondary" variant="subtitle2" sx={{ flex: 1 }}>
              {tstamp}
            </Typography>
          }
        </Grid>

        {swaptoken &&
          <Grid item>
            <JupiterSwap swapfrom={swapfrom} swapto={swapto} portfolioPositions={portfolioPositions} tokenMap={tokenMap}/>
            {/*<OrcaSwap swapfrom={swapfrom} swapto={swapto} portfolioPositions={portfolioPositions} tokenMap={tokenMap} />*/}
          </Grid>
        }
        {token && token === 'sol' &&
          <>
          {/*ftxurl && ftxurl.length > 0 &&
            <Grid item>
              <Button
                  variant="outlined"
                  title="FTX Pay"
                  onClick={handleFTXPay}
                  size="small"
                  >
                  FTX Pay
              </Button>
            </Grid>
          */}
          </>
        }
      </Grid>
    </React.Fragment>
  );
}
