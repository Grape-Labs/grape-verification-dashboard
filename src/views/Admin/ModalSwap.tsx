import React, { useEffect, Suspense, useCallback } from "react";
import { styled } from '@mui/material/styles';
import PropTypes from 'prop-types';
import { AnchorWallet, useAnchorWallet, useConnection, useWallet } from '@solana/wallet-adapter-react';

import {
    Typography,
    Grid,
    Box,
    Button,
    LinearProgress,
} from '@mui/material';

import SwapHorizIcon from "@mui/icons-material/SwapHoriz";

import { GRAPE_RPC_ENDPOINT } from '../../components/Tools/constants';
  
export default function ModalSwapView(props: any){
    const refreshCallback = props.refreshCallback;
    const setLoadingPosition = props?.setLoadingPosition;
    const [loadingSwap, setLoadingSwap] = React.useState(false);
    const { publicKey, wallet } = useWallet();
    const swapfrom = props?.swapfrom;
    const swapto = props?.swapto;
    const toTokenLabel = props?.toTokenLabel
    
    const initJupiter = () => {
        if (wallet) {
            window?.Jupiter.init({
            mode: 'outputOnly',        
            displayMode: 'modal',
            mint: swapto,
            endpoint:GRAPE_RPC_ENDPOINT,
            passThroughWallet: wallet,
            containerStyles: {height: 500},
            onSuccess: ({ txid }) => {
                try{
                    console.log('onSuccess', txid);
                    if (refreshCallback)
                        refreshCallback();
                }catch(err:any){console.log("ERR: "+err)}
            }
          });
        }
    }; 

    return (
        <>
            <Button
                variant="outlined"
                color='inherit'
                onClick={initJupiter}
                size="small"
                sx={{borderRadius:'17px',mr:1}}
            > Swap <SwapHorizIcon /> {toTokenLabel}</Button>
            
        </>
    )
}