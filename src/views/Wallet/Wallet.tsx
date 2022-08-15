import React, { useState, useEffect, ReactElement } from 'react';

import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Tabs,
  Tab,
  Box,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Card,
  CardContent,
  Paper,
  Typography,
  Grid,
  Tooltip,
  Dialog,
  DialogProps,
  IconButton,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
} from '@mui/material/';

import LinkIcon from '@mui/icons-material/Link';
import BoltIcon from '@mui/icons-material/Bolt';
import TollIcon from '@mui/icons-material/Toll';
import QrCodeIcon from '@mui/icons-material/QrCode';

import { decodeMetadata } from './metadataHelper'

import { 
    GRAPE_RPC_ENDPOINT, 
    TX_RPC_ENDPOINT } from '../../components/Tools/constants';
import { PublicKey, Connection, Commitment } from '@solana/web3.js';
import {ENV, TokenInfo, TokenListProvider} from '@solana/spl-token-registry';
import { TokenAmount, lt } from '../../utils/token/safe-math';

import { useWallet } from '@solana/wallet-adapter-react';
import { useSession } from "../../contexts/session";
import { MakeLinkableAddress, ValidateAddress, ValidateCurve } from '../../components/Tools/WalletAddress'; // global key handling

export const WalletView = (props:any) => {
    const { session, setSession } = useSession();
    //const isConnected = session && session.isConnected;
    const wallets = session && session.userWallets;
    const userId = session && session.userId;
    const endpoint = props.endpoint;
    const [loadingWallet, setLoadingWallet] = React.useState(false);
    const [loadingTokens, setLoadingTokens] = React.useState(false);
    const [tokenMap, setTokenMap] = React.useState(null);
    const [loadingPosition, setLoadingPosition] = React.useState(null);
    const [solanaClosableHoldings, setSolanaClosableHoldings] = React.useState(null);
    const [solanaHoldings, setSolanaHoldings] = React.useState(null);
    const [nftCount, setNftCount] = React.useState(0);
    const [tokenCount, setTokenCount] = React.useState(0);
    const [connectedCount, setConnectedCount] = React.useState(0);
    const [nftMap, setNftMap] = React.useState(null);
    const { publicKey, wallet, disconnect } = useWallet();
    const rpclimit = 100;
    const MD_PUBKEY = new PublicKey('metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s');
    const ggoconnection = new Connection(GRAPE_RPC_ENDPOINT);
    
    function getConnected(){
        let servers = session && session.servers;
        const userServers = session && session.userServers;

        if (userServers){
            var count = 0;
            for (var userver of userServers){
                count++;
            }
            setConnectedCount(count);
        }

    }

    const getCollectionData = async (start: number, sholdings: any) => {
        try {
            const mintsPDAs = [];
            
            const mintarr = sholdings
                .slice(rpclimit * start, rpclimit * (start + 1))
                .map((value: any, index: number) => {
                    return value.account.data.parsed.info.mint;
                });

            for (const value of mintarr) {
                if (value) {
                    const mint_address = new PublicKey(value);
                    const [pda, bump] = await PublicKey.findProgramAddress(
                        [Buffer.from('metadata'), MD_PUBKEY.toBuffer(), new PublicKey(mint_address).toBuffer()],
                        MD_PUBKEY
                    );

                    if (pda) {
                        //console.log("pda: "+pda.toString());
                        mintsPDAs.push(pda);
                    }
                }
            }

            //console.log("pushed pdas: "+JSON.stringify(mintsPDAs));
            const final_meta = new Array();
            const metadata = await ggoconnection.getMultipleAccountsInfo(mintsPDAs);
            //console.log("returned: "+JSON.stringify(metadata));
            // LOOP ALL METADATA WE HAVE
            /*
            for (const metavalue of metadata) {
                //console.log("Metaplex val: "+JSON.stringify(metavalue));
                if (metavalue?.data) {
                    try {
                        const meta_primer = metavalue;
                        const buf = Buffer.from(metavalue.data);
                        const meta_final = decodeMetadata(buf);
                        final_meta.push(meta_final)
                    } catch (etfm) {
                        console.log('ERR: ' + etfm + ' for ' + JSON.stringify(metavalue));
                    }
                } else {
                    console.log('Something not right...');
                }
            }
            */
            return metadata;
        } catch (e) {
            // Handle errors from invalid calls
            console.log(e);
            return null;
        }
    };  
  const fetchNFTMetadata = async (holdings:any) => {
    if (holdings){
        const walletlength = holdings.length;

        const loops = Math.ceil(walletlength / rpclimit);
        let collectionmeta: any[] = [];

        const sholdings = new Array();
        for (var item of holdings){
            if (item){
                //console.log("item: "+JSON.stringify(item))
                if (item.account.data.parsed.info.tokenAmount.decimals === 0)
                    sholdings.push(item)
            }
        }

        //console.log('sholdings: ' + JSON.stringify(sholdings));
        
        for (let x = 0; x < loops; x++) {
            const tmpcollectionmeta = await getCollectionData(x, sholdings);
            //console.log('tmpcollectionmeta: ' + JSON.stringify(tmpcollectionmeta));
            collectionmeta = collectionmeta.concat(tmpcollectionmeta);
        }

        const mintarr = sholdings
            .map((value: any, index: number) => {
                return value.account.data.parsed.info.mint;
            });
        
        let nftMap = null;
        if (mintarr){
            //const gql_result = await getGqlNfts(mintarr);
            //nftMap = gql_result;
            //console.log('gql_results: ' + JSON.stringify(nftMap));
        }
        
        const final_collection_meta: any[] = [];
        for (var i = 0; i < collectionmeta.length; i++) {
            //console.log(i+": "+JSON.stringify(collectionmeta[i])+" --- with --- "+JSON.stringify(collectionmeta[i]));
            if (collectionmeta[i]) {
                collectionmeta[i]['wallet'] = sholdings[i];
                try {
                    const meta_primer = collectionmeta[i];
                    const buf = Buffer.from(meta_primer.data, 'base64');
                    const meta_final = decodeMetadata(buf);
                    collectionmeta[i]['meta'] = meta_final;
                    //console.log("meta: "+JSON.stringify(collectionmeta[i]['meta'].mint))
                    try{
                        //console.log("checking: "+collectionmeta[i]['meta'].mint);
                        if (nftMap)
                            //var index = Object.keys(nftMap).indexOf(collectionmeta[i]['meta'].mint);
                            for (const [key, value] of Object.entries(nftMap)){
                                if (key === collectionmeta[i]['meta'].mint){
                                    collectionmeta[i]['image'] = value?.image;
                                    //console.log("image: "+ value?.image);
                                }
                            }
                        //if (collectionmeta.length <= 25) // limitd to 25 fetches (will need to optimize this so it does not delay)
                        //    collectionmeta[i]['urimeta'] = await window.fetch(meta_final.data.uri).then((res: any) => res.json());
                    }catch(err){
                        console.log("ERR: "+err);
                    }
                    collectionmeta[i]['groupBySymbol'] = 0;
                    collectionmeta[i]['groupBySymbolIndex'] = 0;
                    collectionmeta[i]['floorPrice'] = 0;
                    final_collection_meta.push(collectionmeta[i]);
                } catch (e) {
                    console.log('ERR:' + e);
                }
            }
        }

        setNftMap(final_collection_meta);
        return final_collection_meta;
        //console.log('final_collection_meta: ' + JSON.stringify(final_collection_meta));

    }
}

  const fetchSolanaTokens = async () => {
    setLoadingPosition('Tokens');
    //const response = await ggoconnection.getTokenAccountsByOwner(new PublicKey(pubkey), {programId: new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")});
    /*
        let meta_final = JSON.parse(item.account.data);
        let buf = Buffer.from(JSON.stringify(item.account.data), 'base64');
    */
    // Use JSONParse for now until we decode 
    const body = {
        method: "getTokenAccountsByOwner",
        jsonrpc: "2.0",
        params: [
          publicKey.toBase58(),
          { programId: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" },
          { encoding: "jsonParsed", commitment: "processed" },
        ],
        id: "35f0036a-3801-4485-b573-2bf29a7c77d2",
    };
    const resp = await window.fetch(GRAPE_RPC_ENDPOINT, {
        method: "POST",
        body: JSON.stringify(body),
        headers: { "Content-Type": "application/json" },
    })
    const json = await resp.json();
    const resultValues = json.result.value
    //return resultValues;

    let holdings: any[] = [];
    let closable = new Array();
    for (var item of resultValues){
        //let buf = Buffer.from(item.account, 'base64');
        //console.log("item: "+JSON.stringify(item));
        if (item.account.data.parsed.info.tokenAmount.amount > 0)
            holdings.push(item);
        else
            closable.push(item);
        // consider using https://raw.githubusercontent.com/solana-labs/token-list/main/src/tokens/solana.tokenlist.json to view more details on the tokens held
    }

    let sortedholdings = JSON.parse(JSON.stringify(holdings));
    sortedholdings.sort((a:any,b:any) => (b.account.data.parsed.info.tokenAmount.amount - a.account.data.parsed.info.tokenAmount.amount));

    var solholdingrows = new Array()
    var cnt = 0;

    let cgArray = '';//new Array()
    for (var item of sortedholdings){
        //console.log("item: "+JSON.stringify(item))
        const tm = tokenMap.get(item.account.data.parsed.info.mint)
        if (tm && tm?.extensions?.coingeckoId){
            if (cgArray.length > 0)
                cgArray += ',';
            cgArray+=tm.extensions.coingeckoId
            item.coingeckoId = tm.extensions.coingeckoId;
            //cgArray.push(tm.extensions.coingeckoId)
        }

    }    

    //setLoadingPosition('Prices');
    //const cgPrice = await getCoinGeckoPrice(cgArray);

    setLoadingPosition('NFT Metadata');
    const nftMeta = await fetchNFTMetadata(sortedholdings);

    let nft_count = 0;
    let token_count = 0;
    //console.log("nftMeta: "+JSON.stringify(nftMeta))

    for (var item of sortedholdings){
        /*
        try{
            const tknPrice = await getTokenPrice(item.account.data.parsed.info.mint, "USDC");
            item.account.data.parsed.info.tokenPrice = tknPrice.data.price
        }catch(e){}
        */
        
        const itemValue = 0;//+cgPrice[item?.coingeckoId]?.usd ? (cgPrice[item.coingeckoId].usd * parseFloat(new TokenAmount(item.account.data.parsed.info.tokenAmount.amount, item.account.data.parsed.info.tokenAmount.decimals).format())).toFixed(item.account.data.parsed.info.tokenAmount.decimals) : 0;
        const itemBalance = Number(new TokenAmount(item.account.data.parsed.info.tokenAmount.amount, item.account.data.parsed.info.tokenAmount.decimals).format().replace(/[^0-9.-]+/g,""));
        
        if (item.account.data.parsed.info.tokenAmount.decimals === 0)
            nft_count++;
        else
            token_count++;

        let logo = null;
        let name = item.account.data.parsed.info.mint;
        let metadata = null;

        var foundMetaName = false;
        for (var nft of nftMeta){
            //console.log('meta: '+JSON.stringify(nft));
            if (nft.meta.mint === item.account.data.parsed.info.mint){
                //console.log("nft: "+JSON.stringify(nft))
                
                name = nft.meta.data.name;
                metadata = nft.meta.data.uri;
                // fetch
                if (nft?.image)
                    logo = nft.image;
                else if (nft?.urimeta?.image)
                    logo = nft.urimeta?.image;
                foundMetaName = true;
            }
        }
        
        if (!foundMetaName){
            name = tokenMap.get(item.account.data.parsed.info.mint)?.name;
            logo = tokenMap.get(item.account.data.parsed.info.mint)?.logoURI;
        }
        if ((name && name?.length <= 0) || (!name))
            name = item.account.data.parsed.info.mint;
        
        solholdingrows.push({
            id:cnt,
            mint:item.account.data.parsed.info.mint,
            logo: {
                mint: item.account.data.parsed.info.mint,
                logo: logo,
                metadata: metadata
            },
            name:name,
            balance:itemBalance,
            //price:item.account.data.parsed.info.tokenAmount.decimals === 0 ? 0 : cgPrice[item?.coingeckoId]?.usd || 0,
            //change:item.account.data.parsed.info.tokenAmount.decimals === 0 ? 0 : cgPrice[item?.coingeckoId]?.usd_24h_change || 0,
            value: +itemValue,
            send:item.account.data.parsed.info,
            //swap:item.account.data.parsed.info
        });
        cnt++;
    }

    let closableholdingsrows = new Array();
    cnt = 0;
    for (var item of closable){
        /*
        try{
            const tknPrice = await getTokenPrice(item.account.data.parsed.info.mint, "USDC");
            item.account.data.parsed.info.tokenPrice = tknPrice.data.price
        }catch(e){}
        */
        
        const itemValue = 0;
        const itemBalance = 0;
        
        closableholdingsrows.push({
            id:cnt,
            mint:item.account.data.parsed.info.mint,
            logo: {
                mint: item.account.data.parsed.info.mint
            },
            name:tokenMap.get(item.account.data.parsed.info.mint)?.name || item.account.data.parsed.info.mint,
            balance:itemBalance,
            oncurve: ValidateCurve(item.account.data.parsed.info.mint),
            nft: item.account.data.parsed.info.tokenAmount.decimals === 0 ? true : false,
            close:item.account.data.parsed.info,
            preview:item.account.data.parsed.info.mint
        });
        cnt++;
    }

    setSolanaClosableHoldings(closable);
    setSolanaHoldings(sortedholdings);
    setNftCount(nft_count);
    setTokenCount(token_count);
} 

  const fetchTokens = async () => {
        setLoadingPosition('Wallet');
        const tokens = await new TokenListProvider().resolve();
        const tokenList = tokens.filterByChainId(ENV.MainnetBeta).getList();
        const tokenMapValue = tokenList.reduce((map, item) => {
            map.set(item.address, item);
            return map;
        }, new Map())
        setTokenMap(tokenMapValue);
        return tokenMapValue;
    }

    const fetchTokenPositions = async () => {
        setLoadingTokens(true);
        await fetchSolanaTokens();
        getConnected();
        setLoadingTokens(false);
    }

  React.useEffect(() => {
    if (publicKey && tokenMap){
        fetchTokenPositions();
    }
}, [tokenMap]);

  const fetchWalletPositions = async () => {
    setLoadingWallet(true);
    const tmap = await fetchTokens();
    setLoadingWallet(false);
}


  React.useEffect(() => {
    if (publicKey){
        fetchWalletPositions();
    }
  }, [publicKey]);

  return (
    <Grid item xs={12} sx={{mt:4}}>
        <Box sx={{ flexGrow: 1 }} className="grape-paper-background">
            <Grid 
            container
            spacing={0}
            alignContent="center"
            justifyContent="center"
            direction="row"
            >
                
                    
                {publicKey ?
                <>
                    {loadingTokens || loadingWallet ?
                    <>loading {loadingPosition}</>
                    :
                        <Grid container>
                            <Grid item xs={12} sm={3}>
                                <Grid container
                                    alignContent="center"
                                    justifyContent="center"
                                >
                                    <Grid item>
                                        <QrCodeIcon sx={{ fontSize: 30, mr:1, color:'rgba(255,255,255,0.5)'}} />
                                    </Grid>
                                    <Grid item>
                                        <Typography variant='h5' sx={{color:'rgba(255,255,255,0.5)'}}>
                                            NFTs: {nftCount}
                                        </Typography>
                                    </Grid>
                                </Grid>
                            </Grid>
                            <Grid item xs={12} sm={3}>
                                <Grid container                                
                                    alignContent="center"
                                    justifyContent="center"
                                >
                                    <Grid item>
                                        <TollIcon  sx={{ fontSize: 30, mr:1, color:'rgba(255,255,255,0.5)'}} />
                                    </Grid>
                                    <Grid item>
                                        <Typography variant='h5' sx={{color:'rgba(255,255,255,0.5)'}}>
                                            Tokens: {tokenCount}
                                        </Typography>
                                    </Grid>
                                </Grid>
                            </Grid>
                            <Grid item xs={12} sm={3}>
                                <Grid container                                
                                    alignContent="center"
                                    justifyContent="center"
                                >
                                    <Grid item>
                                        <LinkIcon  sx={{ fontSize: 30, mr:1, color:'rgba(255,255,255,0.5)'}} />
                                    </Grid>
                                    <Grid item>
                                        <Typography variant='h5' sx={{color:'rgba(255,255,255,0.5)'}}>
                                            Connected: {connectedCount}
                                        </Typography>
                                    </Grid>
                                </Grid>
                            </Grid>
                            <Grid item xs={12} sm={3}>
                                <Grid container                                
                                    alignContent="center"
                                    justifyContent="center"
                                >
                                    <Grid item>
                                        <BoltIcon  sx={{ fontSize: 30, mr:1, color:'rgba(255,255,255,0.15)'}} />
                                    </Grid>
                                    <Grid item>
                                        <Typography variant='h5' sx={{color:'rgba(255,255,255,0.15)'}}>
                                            Auto: soon
                                        </Typography>
                                    </Grid>
                                </Grid>
                            </Grid>
                            
                            <Grid container                                
                                    alignContent="center"
                                    justifyContent="center"
                                >
                                <Button
                                    href='https://grape.art/identity'
                                    target='_blank'
                                    variant='outlined'
                                    sx={{textTransform:'none',mt:2}}
                                >View &amp; manage your wallet at Grape Identity</Button>
                            </Grid>
                            {/*solanaHoldings && solanaHoldings.map((item: any, key: number) => (
                                    <ListItem>
                                        {
                                        tokenMap.get(item.account.data.parsed.info.mint)?.name || 
                                        item.account.data.parsed.info.mint}
                                    </ListItem>
                                ))*/}
                                {/*console.log(JSON.stringify(solanaHoldings))*/}
                        </Grid> 
                    }
                </>
                :<>Connect to view your wallet summary</>}
                
            </Grid>
        </Box>
    </Grid>
  );
}

