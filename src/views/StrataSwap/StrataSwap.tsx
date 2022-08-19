import * as React from 'react';
import * as anchor from "@project-serum/anchor";
import { Provider, AnchorProvider } from "@project-serum/anchor";
import { useConnection, useWallet } from '@solana/wallet-adapter-react';
import { BN } from "bn.js";
import { SplTokenBonding } from "@strata-foundation/spl-token-bonding";
import { SplTokenCollective } from "@strata-foundation/spl-token-collective";
import { getAssociatedAccountBalance, SplTokenMetadata } from "@strata-foundation/spl-utils";
import { PublicKey, Connection } from '@solana/web3.js';
import { Wallet as NodeWallet } from "@project-serum/anchor";
import {useSnackbar} from "notistack";

import {
    Button,
 } from '@mui/material';

import { 
    GRAPE_RPC_ENDPOINT, 
    TX_RPC_ENDPOINT } from '../../components/Tools/constants';

export default function StrataSwap(props: any) {
    const swapAmount = props.swapAmount || 1;
    const swapFrom = props.swapFrom || '8upjSpvjcdpuzhfR1zriwg5NXkwDruejqNE9WNbPRtyA';
    const swapTo = props.swapTo || '4BF5sVW5wRR56cy9XR8NFDQGDy5oaNEFrCHMuwA9sBPd'; 
    const connection = new Connection(GRAPE_RPC_ENDPOINT);
    //const provider = anchor.getProvider();
    const { publicKey } = useWallet();
    const wallet = useWallet();
    const provider = new AnchorProvider(connection, wallet, {});
    const { enqueueSnackbar, closeSnackbar } = useSnackbar();

    const swapUsingStrata = async () => {
        const tokenBondingSdk = await SplTokenBonding.init(provider);
        /*
        tokenBondingSdk.getPricing(
            new PublicKey(swapTo)
        )
        */
       
        enqueueSnackbar(`Preparing to swap GRAPE for ${swapAmount} GAN`,{ variant: 'info' });

        var mintTokenRef = (await SplTokenCollective.mintTokenRefKey(new PublicKey(swapTo)))[0];
        console.log("mintTokenRef: "+JSON.stringify(mintTokenRef))
        /*
        var { targetAmount } = await tokenBondingSdk.swap({
            baseMint: new PublicKey(swapFrom),
            targetMint: new PublicKey(swapTo),
            baseAmount: swapAmount,
            slippage: 0.05,
          });
        */

        var tokenBondingKey = (
            await SplTokenBonding.tokenBondingKey(new PublicKey(swapTo))
        )[0];
        var openCollectiveBonding = await tokenBondingSdk.getTokenBonding(
            tokenBondingKey
        );
        
        const signedTransaction = await tokenBondingSdk.buy({
            tokenBonding: tokenBondingKey,
            desiredTargetAmount: 0.0001, //swapAmount
            slippage: 0.05,
        });


        
        /*
        await tokenBondingSdk.buy({
            tokenBonding: SplTokenCollective.OPEN_COLLECTIVE_BONDING_ID,
            desiredTargetAmount: 1,
            slippage: 0.05,
        });
        var openBalance = await getAssociatedAccountBalance(
            connection,
            publicKey,
            tokenBondingAcct.baseMint
        );
        */
    }

    const setupStrata = async () => {
        //const tokenCollectiveSdk = await SplTokenCollective.init(new Provider(connection, new NodeWallet(payerServiceAccount), {}));
        const tokenCollectiveSdk = await SplTokenCollective.init(provider);
        const tokenBondingSdk = await SplTokenBonding.init(provider);
        const tokenMetadataSdk = await SplTokenMetadata.init(provider);
    }

    React.useEffect(() => {
        setupStrata();
    }, []);

    return (
        <>
            <Button 
                variant='outlined'
                onClick={() => {
                    swapUsingStrata();
                }}
                sx={{borderRadius:'17px'}}
            >
                Get 1 GAN with Grape
            </Button>
        </>
    );
}