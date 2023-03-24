import * as React from 'react';
import { WalletAdapterNetwork } from '@solana/wallet-adapter-base';
import { useWallet } from '@solana/wallet-adapter-react';
import { AccountsProvider } from './contexts/accounts';
import AppStateProvider from './contexts/appstate';
import { AppStateContext } from './contexts/appstate';
import { MoneyStreamsPage } from '../../components/MoneyStreamsPage';
import {
    Typography,
    Grid,
    Box,
    Paper,
    Skeleton,
} from '@mui/material/';
import { SnackbarUtilsConfigurator } from './helpers/SnackBarUtils';
import "./Meanfi.css";
import { GRAPE_RPC_ENDPOINT } from './constants';

const MeanfiUiView = (props: any) => {
    const [loading, setLoading] = React.useState(true);
    const { publicKey } = useWallet();
    const { tokenList } = React.useContext(AppStateContext);

    React.useEffect(() => {
        if (tokenList && tokenList.length > 0) {
            setLoading(false);
        }
    }, [tokenList]);

    if (loading) {
        return (
            <React.Fragment>
                <Grid item xs={12}>
                    <Paper className="grape-paper-background">
                        <Paper
                            className="grape-paper"
                            sx={{
                                p: 2,
                                display: 'flex',
                                flexDirection: 'column',
                            }}>
                            <Box sx={{ p: 1, width: "100%" }}>
                                <Skeleton />
                            </Box>
                        </Paper>
                    </Paper>
                </Grid>
            </React.Fragment>
        )
    } else {
        if (publicKey && tokenList) {
            return (
                <>
                    <SnackbarUtilsConfigurator />
                    <MoneyStreamsPage />
                </>
            );
        } else {
            return (<></>);
        }

    }
}

///////////////////////
//  Main entrypoint  //
///////////////////////

export function MeanfiView(props: any) {

    // Fallback values if not passed (.Devnet | .Mainnet)
    const network = WalletAdapterNetwork.Mainnet;
    const endpoint = GRAPE_RPC_ENDPOINT;

    return (
        <AppStateProvider network={network} endpoint={endpoint}>
            <AccountsProvider>
                <MeanfiUiView />
            </AccountsProvider>
        </AppStateProvider>
    );
}
