import * as React from "react";
import { useEffect, useState } from "react";
import { NavLink } from 'react-router-dom';
import { TokenListProvider, TokenInfo } from '@solana/spl-token-registry';
import { getProfilePicture } from '@solflare-wallet/pfp';
import { delay } from "../../views/Meanfi/helpers/ui";
import { useConnection } from '@solana/wallet-adapter-react';

import{
  Typography,
  Paper,
  Grid,
  Box,
  Divider,
  Chip,
  Tab,
  Tabs,
  Button,
  Skeleton,
  Tooltip,
  Avatar,
} from '@mui/material/'

import PropTypes from 'prop-types';

import { useSession } from "../../contexts/session";
import Summary from '../Summary/Summary';
import PortfolioTable from './PortfolioTable';
import { struct } from 'buffer-layout';
import { publicKey, u128, u64 } from '@project-serum/borsh'
import { TokenAmount, lt } from '../../utils/token/safe-math';

//import { useTheme } from '@mui/material/styles';
import {PublicKey} from '@solana/web3.js';
import { PretifyCommaNumber } from '../../components/Tools/PretifyCommaNumber';
import { RPC_ENDPOINT } from '../../components/Tools/constants';

import CachedIcon from '@mui/icons-material/Cached';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import ArrowUpwardIcon from '@mui/icons-material/ArrowUpward';
import ArrowDownwardIcon from '@mui/icons-material/ArrowDownward';
import ImageIcon from '@mui/icons-material/Image';
import CircularProgress from '@mui/material/CircularProgress';
import RefreshIcon from '@mui/icons-material/Refresh';
import GrapeIcon from '../../components/StaticIcons/GrapeIcon';
import SolIcon from '../../components/StaticIcons/SolIcon';
import SolCurrencyIcon from '../../components/StaticIcons/SolCurrencyIcon';

import { FarmsView } from "../";

  const USER_STAKE_INFO_ACCOUNT_LAYOUT = struct([
    u64('state'),
    publicKey('poolId'),
    publicKey('stakerOwner'),
    u64('depositBalance'),
    u64('rewardDebt')
  ])

  function TabPanel(props) {
    const { children, value, index, ...other } = props;
    return (
      <div
        role="tabpanel"
        hidden={value !== index}
        id={`simple-tabpanel-${index}`}
        aria-labelledby={`simple-tab-${index}`}
        {...other}
      >
        {value === index && (
          <Box sx={{ p: 3 }}>
            <Typography>{children}</Typography>
          </Box>
        )}
      </div>
    );
  }
  
  TabPanel.propTypes = {
    children: PropTypes.node,
    index: PropTypes.number.isRequired,
    value: PropTypes.number.isRequired,
  };
  
  function a11yProps(index) {
    return {
      id: `simple-tab-${index}`,
      'aria-controls': `simple-tabpanel-${index}`,
    };
  }

export const PortfolioView = () => {
  const [initPortfolio, setInitPortfolio] = useState(null);
  const [initCGPriceData, setInitCGPriceData] = useState(null);
  const [initRaydiumPriceData, setInitRaydiumPriceData] = useState(null);
  const [initNewPriceData, setInitNewPriceData] = useState(null);
  const [portfolioPositions, setPorfolioBalances] = useState(null);
  const [tokenMap, setTokenMap] = useState(new Map());
  const { session, setSession } = useSession();
  const [grapeTicker, setGrapeTicker] = useState(null);
  const [solTicker, setSolTicker] = useState(null);
  const [tstamp, setTickerTimestamp] = useState(null);
  const [value, setTabValue] = React.useState(0);
  const [profilePictureUrl, setProfilePicutureUrl] = React.useState(null);
  const [hasProfilePicture, setHasProfilePicture] = React.useState(false);
  const { connection } = useConnection();

  const [loading, setLoading] = React.useState(false);
  const [success, setSuccess] = React.useState(false);
  const [array, setArray] = useState([]);

  const handleTabChange = (event, newValue) => {
    setTabValue(newValue);
  };

  //const connection = new Connection(url, "singleGossip");
  //const orca = getOrca(connection);
  //const owner: Keypair = getKeyPair();

  //RAYDIUM: /logos/platforms/raydium.png
  //SOLFARM: /logos/platforms/solfarm.png
  //ORCA: /logos/platforms/orca.png

  //Get Balances RPC
  const fetchStakedRaydium = async () => {
    const body = {
        method: "getProgramAccounts",
        //method: "getMultipleAccountsInfo",
        jsonrpc: "2.0",
        params: [
            "9KEPoZmtHUrBbhWN1v1KWLMkkvwY6WLtAVUCPRtRjP4z",
            //"97q89hnoKwqcynvwXcj83YqfqUBuCm4A8f2zHeV6bfZg", ORCA/GRAPE
            //session.publicKey
            //"9KEPoZmtHUrBbhWN1v1KWLMkkvwY6WLtAVUCPRtRjP4z", // raydium stakes
            {"commitment":"confirmed","filters":[{"memcmp":{"offset":40,"bytes":session.publicKey}}],"encoding":"base64"}
            //{"connection":"Connection","publicKeys": [session.publicKey]}
        ],
        id: "84203270-a3eb-4812-96d7-0a3c40c87a88"
      };
      
      const response = await fetch(RPC_ENDPOINT, {
        method: "POST",
        body: JSON.stringify(body),
        headers: { "Content-Type": "application/json" },
      });
      
      const json = await response.json();
      let decoded = json.result && json.result.map(({ pubkey, account: { data, executable, owner, lamports } }) => ({
        publicKey: new PublicKey(pubkey),
        accountInfo: {
          data: Buffer.from(data[0], 'base64'),
          executable,
          owner: new PublicKey(owner),
          lamports
        }}));

        return decoded;
  }

  const fetchPairsSolFarm = async () => {
    const response = await fetch("https://api.raydium.io/pairs", {
        method: "GET",
        headers: { "Content-Type": "application/json" },
    });

    const json = await response.json();
    return json;
  }

  const fetchPairsOrca = async () => {
    // ORCA token:
    // orcaEKTdK7LKz57vaAYr9QeNsVEPfiu6QeMU1kektZE
    // ORCA pool:
    // 97q89hnoKwqcynvwXcj83YqfqUBuCm4A8f2zHeV6bfZg

    /* CONSIDERING THEIR API:
    const connection = new Connection(url, "singleGossip");
    const orca = getOrca(connection);
    
    // Get an instance of the ETH-USDC orca pool
    let pool = orca.getPool(OrcaPoolConfig.GRAPE_USDC);

    // Get the number of ETH-USDC LP tokens in your wallet
    let grapeUsdcLPBalance = await pool.getLPBalance(owner.publicKey);
    // Get the total supply of ETH-USDC LP tokens
    let grapeUsdcLPSupply = await pool.getLPSupply();
    
    */
    const response = await fetch("https://api.orca.so/allPools", {
        method: "GET",
        headers: { "Content-Type": "application/json" },
    });

    const json = await response.json();
    return json;
  }

  const fetchPairsRaydium = async () => {
    const response = await fetch("https://api.raydium.io/pairs", {
        method: "GET",
        headers: { "Content-Type": "application/json" },
    });

    const json = await response.json();
    return json;
  }

  const fetchAdditionalFarmPools = async () => {

    // get Orca (we should function this out though)
    const response = await fetch("https://api.orca.so/allPools", {
        method: "GET",
        headers: { "Content-Type": "application/json" },
    });

    const json = await response.json();
    return json;
  }

  const fetchBalances = async () => {
    const body = {
      method: "getTokenAccountsByOwner",
      jsonrpc: "2.0",
      params: [
        // Get the public key of the account you want the balance for.
        session.publicKey,
        { programId: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" },
        { encoding: "jsonParsed", commitment: "processed" },
      ],
      id: "35f0036a-3801-4485-b573-2bf29a7c77d2",
    };

    //try{
      const response = await fetch(RPC_ENDPOINT, {
        method: "POST",
        body: JSON.stringify(body),
        headers: { "Content-Type": "application/json" },
      })
      const json = await response.json();
      const resultValues = json.result.value
      return resultValues;
  };

  const fetchSOLBalance = async () => {
    const body = {
      method: "getBalance",
      jsonrpc: "2.0",
      params: [
        // Get the public key of the account you want the balance for.
        session.publicKey
      ],
      id: "35f0036a-3801-4485-b573-2bf29a7c77d3",
    };

    const response = await fetch(RPC_ENDPOINT, {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
    });

    const json = await response.json();
    const resultValues = json.result.value;
    return resultValues;
  };

  //Get Prices RPC
  const fetchNSWPriceList = async () => {
    const response = await fetch("https://api.sonar.watch/latest", {
      method: "GET",
      //body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
    }).catch((error)=>{
      console.log("ERROR GETTING CG DATA!");
      return null;
    });
    
    try{
      const json = await response.json();
      return json;
    }catch(e){return null;}
  }

    //Get Raydium Prices
    const fetchRaydiumPriceList = async () => {
      
      const response = await fetch("https://api.raydium.io/coin/price", {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      }).catch((error)=>{
        console.log("ERROR GETTING RAYDIUM DATA!");
        return null;
      });
      
      try{
        const json = await response.json();
        return json;
      }catch(e){return null;}
      
      /*
      return fetch(path || "https://api.raydium.io/coin/price", {
        method: "GET",
      })
      .then((response) => response.json())
      .then((response) => {
        return response;
      })
      .catch((err) => {
        console.error(err);
      });
      */

    }

  //Get Prices RPC
  const fetchCoinGeckoPriceList = async () => {
    const response = await fetch("https://api.coingecko.com/api/v3/simple/price?include_24hr_change=true&ids=solana,kitty-solana,astrapad,buff-samo,solana-inu,wipemyass,almond,swole-doge,oogi,solex-finance,bamboo-coin,solum,solberg,sola-token,solana,usd-coin,everid,impossible-finance,investin,bitcoin,ethereum,yearn-finance,chainlink,ripple,tether,sushi,aleph,swipe,hedget,cream-2,upbots,helium,frontier-token,akropolis,hxro,uniswap,serum,ftx-token,megaserum,usd-coin,tomochain,karma-dao,lua-token,math,keep-network,swag-finance,celsius-degree-token,reserve-rights-token,1inch,the-graph,compound-coin,pax-gold,strong,bonfida,kin,maps,oxygen,brz,tether,xmark,raydium,bitsong,3x-short-eos-token,3x-long-eos-token,3x-short-bnb-token,3x-long-bnb-token,3x-long-bitcoin-sv-token,3x-short-bitcoin-sv-token,3x-short-litecoin-token,3x-long-litecoin-token,3x-long-bitcoin-token,3x-short-bitcoin-token,3x-short-bitcoin-cash-token,3x-long-bitcoin-cash-token,3x-long-ethereum-token,3x-short-ethereum-token,3x-long-altcoin-index-token,3x-short-altcoin-index-token,3x-long-shitcoin-index-token,3x-short-shitcoin-index-token,3x-long-midcap-index-token,3x-short-midcap-index-token,3x-short-chainlink-token,3x-long-chainlink-token,3x-long-xrp-token,3x-short-xrp-token,1x-long-btc-implied-volatility-token,1x-short-btc-implied-volatility,aave,serum-ecosystem-token,holy-trinity,bilira,3x-long-dogecoin-token,perpetual-protocol,weth,coin-capsule,ftx-token,true-usd,tokenlon,allianceblock,skale,unlend-finance,orion-protocol,sparkpoint,uma,smartkey,mirror-protocol,growth-defi,xdai-stake,yearn-finance,basic-attention-token,basic-attention-token,decentraland,xio,unilayer,unimex-network,1inch,armor,armor-nxm,defipulse-index,deltahub-community,kira-network,energy-web-token,cryptocurrency-top-10-tokens-index,audius,vesper-finance,keep3rv1,lead-token,uniswap,wrapped-bitcoin,union-protocol-governance-token,unisocks,idextools,hex,cream-2,yfimobi,zeroswap,wrapped-anatha,ramp,parsiq,smooth-love-potion,the-sandbox,concentrated-voting-power,republic-protocol,sora,funfair,pickle-finance,pax-gold,quant-network,oraichain-token,truefi,mcdex,nucypher,razor-network,chainlink,unfederalreserve,nusd,hegic,xfinance,dextf,iexec-rlc,cvault-finance,cyberfi,wise-token11,gnosis,poolz-finance,dai,sushi,fyooz,quiverx,unitrade,bird-money,axion,bridge-mutual,dynamite,bitberry-token,waxe,matic-network,robonomics-network,aave,ethlend,polkastarter,unibright,dia-data,frax,keep-network,reserve-rights-token,88mph,paid-network,swipe,request-network,whale,kleros,krown,apy-finance,ocean-protocol,shopping-io,binance-wrapped-btc,unistake,maker,harvest-finance,usd-coin,aragon,pundi-x,redfox-labs-2,meta,rubic,noia-network,celsius-degree-token,crowns,option-room,yield-optimization-platform,lgcy-network,rio-defi,mahadao,rocket-pool,nexo,saffron-finance,stabilize,balancer,band-protocol,swapfolio,loopring,perpetual-protocol,compound-governance-token,havven,dlp-duck-token,chain-games,the-graph,rootkit,trustswap,terra-virtua-kolect,omisego,wrapped-terra,bondly,dextrust,ampleforth,polkamarkets,curve-dao-token,degenerator,exnetwork-token,tether,yield,kyber-network,coti,injective-protocol,0x,superfarm,ankreth,surf-finance,renbtc,dmm-governance,hermez-network-token,rally-2,yfdai-finance,fractal,axie-infinity,enjincoin,yield-app,duckdaodime,rarible,amp-token,fsw-token,binance-usd,aave-dai-v1,aave-tusd-v1,aave-usdc-v1,aave-usdt-v1,aave-susd-v1,aave-bat-v1,aave-eth-v1,aave-link-v1,aave-knc-v1,aave-mkr-v1,aave-mana-v1,aave-zrx-v1,aave-snx-v1,aave-wbtc-v1,aave-busd-v1,aave-enj-v1,aave-ren-v1,ayfi,aave-usdt,aave-wbtc,aave-zrx,aave-bat,aave-busd,aave-dai,aave-enj,aave-knc,aave-link,aave-mana,aave-mkr,aave-ren,aave-snx,aave-susd,aave-tusd,aave-usdc,stake-dao,cope,cope,mango-market-caps,rope-token,media-network,step-finance,solanium,samoyedcoin,panda-coin,star-atlas,star-atlas-dao,soldoge,synthetify-token,moonlana,solape-token,woof-token,mercurial,lotto,bole-token,apyswap,shibaverse-token,shibaverse-token,solfarm,ardcoin,cheems,cato,ninja-protocol,boring-protocol,dexlab,grape-2,apexit-finance,black-label,orca,renbtc,renbch,rendoge,renzec,sail,aldrin,oxbull-solana,fabric,naxar,space-hamster,gu,liq-protocol,cropperfinance,solrise-finance,jet,cheesesoda-token,only1,terrausd,orbs,solberry,coin98,saber,huobi-btc,husd,hapi,larix,msol,mim,port-finance,jpyc,mango-markets,solanasail-governance-token,parrot-usd,parrot-protocol,sunny-aggregator,cyclos,lido-staked-ether,million,million,shapeshift-fox-token,ashera,balisari,solminter,tether,usd-coin,renfil,bitspawn,socean-staked-sol,agronomist,polyplay,allbridge,binance-usd,weth,tether,usd-coin,multi-collateral-dai,celo-dollar,chihuahuasol,chronologic,ftx-token,matrixetf,solblank,marinade,wrapped-conceal,graviton,dogelana,usd-coin,bitcoin,solana,ftx-token,ethereum,usd-coin,tether,dai,himalayan-cat-coin,frakt-token,tether,usd-coin,multi-collateral-dai,wrapped-bitcoin,avalanche,aurory,matrixetf,lizard-token,cave,ftx-token,terra-usd,weth,serum,terra-luna,husd,binance-usd,frax,huobi-btc,usdk,sushi,uniswap,wbnb,chainlink,pax-gold,hxro,swipe,frax-share,celsius-network-token,cream,usd-coin,wrapped-bitcoin,tether,floof,baby-samo-coin,solend,lunachow,lunachow,biconomy-exchange-token,ariadne,solana,invictus,wrapped-bitcoin,polygon,polygon,binance-usd,the-4th-pillar,genopets,safe-coin-2&vs_currencies=usd",{
      method: "GET",
      //body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
    }).catch((error)=>{
      console.log("ERROR GETTING CG DATA!");
      return null;
    });
    
    try{
      const json = await response.json();
      return json;
    }catch(e){return null;}
  }

  //Get Prices RPC
  const fetchLegacyPriceList = async () => {
    const response = await fetch("https://price-api.sonar.watch/prices", {
      method: "GET",
      //body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
    }).catch((error)=>{
      console.log("ERROR GETTING SW DATA!");
      return [];
    });
    
    try{
      const json = await response.json();
      return json;
    }catch(e){return null;}
  }

  const fetchTokenMap = async () => {
    let tokens = await new TokenListProvider().resolve();
    const tokenList = tokens.filterByClusterSlug('mainnet-beta').getList();

    let tokenMap = tokenList.reduce((map, item) => {
      map.set(item.address, item);
      return map;
    }, new Map());

    return tokenMap;
  }

  //Get Porfolio
  const getBalances = async () => {
    if (!loading){
      
      setSuccess(false);
      setLoading(true);
      
      let [portfolio, tokenMap] = await Promise.all([fetchBalances(), fetchTokenMap()]);
      
      // first load a skeleton of the portfolio
      // then fetch cg
      let [cgPriceData, raydiumPriceData] = await Promise.all([fetchCoinGeckoPriceList(), fetchRaydiumPriceList()]);

      // finally check farms (this can break so lets split)
      let [sol, newPriceData] = await Promise.all([fetchSOLBalance(), fetchNSWPriceList()]);
      
      setInitNewPriceData(newPriceData);
      setInitPortfolio(portfolio);
      setInitCGPriceData(cgPriceData);
      setInitRaydiumPriceData(raydiumPriceData);
      setTokenMap(tokenMap);
      
      // we need to now first get portfolio 
      // then load a skeleton (without positions)
      // then load positions from fetched data from cg or other source
      // then loa

      let legacyPriceData = [];
      //let [newPriceData] = [null];
      
      let other_stakes = [];
      const tmint = '8upjSpvjcdpuzhfR1zriwg5NXkwDruejqNE9WNbPRtyA';
      const grapesymbol = 'grape-2';
      
      const smint = 'So11111111111111111111111111111111111111112';
      const solanasymbol = 'solana';

      let grapeTokenReference = null;
      let solTokenReference = null;
      
      let priceData = [];

      if (!newPriceData){
        [legacyPriceData] = await Promise.all([fetchLegacyPriceList()]);
        
        if (!legacyPriceData)
          console.log("NO DATA");
      }
      // check which data we have loaded so we can parse accordingly

      if (!newPriceData){ // reverting to legacy
        grapeTokenReference = legacyPriceData.find(grapeTokenReference => grapeTokenReference.mint === tmint);
        grapeTokenReference = grapeTokenReference && grapeTokenReference.price;
        solTokenReference = legacyPriceData.find(solTokenReference => solTokenReference.mint === smint);
        solTokenReference = solTokenReference && solTokenReference.price;
        priceData = legacyPriceData;
      }else {
      
        if (newPriceData.prices.hasOwnProperty(tmint))
          grapeTokenReference = newPriceData.prices[tmint].value;

        if (newPriceData.prices.hasOwnProperty(smint))
          solTokenReference = newPriceData.prices[smint].value;

      }
      
      setTickerTimestamp((new Date()).toLocaleString());

      let collectibles = [];

      portfolio = portfolio.map((token) => {
        let mint = token.account.data.parsed.info.mint;
        let balance = token.account.data.parsed.info.tokenAmount.uiAmount;
        let tmapitem = mint && tokenMap.get(mint);
        let price = (tmapitem && tmapitem.extensions?.coingeckoId) && cgPriceData[tmapitem.extensions.coingeckoId]?.usd || 0;
        let usd_24h_change = (tmapitem && tmapitem.extensions?.coingeckoId) && cgPriceData[tmapitem.extensions.coingeckoId]?.usd_24h_change || '';

        if (tmapitem){  
          if (tmapitem.extensions?.coingeckoId){

            // handle prices not on CG
            if (price === 0){ // check raydium pool data
              if ((tmapitem) && (tmapitem.symbol) && raydiumPriceData) {
                try{                  
                  if (raydiumPriceData[tmapitem.symbol.toUpperCase()])
                    price = raydiumPriceData[tmapitem.symbol.toUpperCase()];
                }catch(e){console.log("ERR:"+e)}
              }
             }

              priceData.push({
                address: token.pubkey,
                decimals: token.decimals,
                mint: mint,
                symbol: tmapitem && tmapitem.symbol || 'Unknown',
                logoURI: tmapitem && tmapitem.logoURI || '',
                price: price,
                usd_24h_change: usd_24h_change,
                updatedAt: ''
              }); 

            //}catch(e){console.log("ERR: "+e)}
          }
          
        }
        //var price = 0;
        //if (priceData)
          //price = priceData.find(price => price.mint === token.account.data.parsed.info.mint);
        
        // Fetch collectibles
        try{
            (+token.account.data.parsed.info.tokenAmount.amount >= 1) &&
              (+token.account.data.parsed.info.tokenAmount.decimals === 0) && 
                  collectibles.push(token);    
        } catch(e){console.log(e);}
        
        return {
          address: token.pubkey,
          decimals: token.decimals,
          mint: mint,
          symbol: tmapitem && tmapitem.symbol || 'Unknown',
          coingeckoId: tmapitem && tmapitem?.extensions?.coingeckoId || '',
          balance: balance,
          price: price && price,
          value: price && price * balance,
          tokenInfo: mint && tokenMap.get(mint),
          usd_24h_change: usd_24h_change
        };
        
      }).filter((token) => {
        return (token.balance > 1) &&  (token.decimals !== 0) && typeof token.balance !== "undefined";
      });
      
      if (sol){ // use sol calc for balance
          sol = parseFloat(new TokenAmount(sol, 9).format());
          const mint = 'So11111111111111111111111111111111111111112';
          
          //var price = priceData.find(price => price.mint === mint);
          //price = price && price.price;
          let tokenInfo = tokenMap.get(mint);
          tokenInfo.name = "SOL";

          let tmapitem = mint && tokenMap.get(mint);
          let price = (tmapitem && tmapitem.extensions?.coingeckoId) && cgPriceData[tmapitem.extensions.coingeckoId]?.usd || 0;
          let usd_24h_change = (tmapitem && tmapitem.extensions?.coingeckoId) && cgPriceData[tmapitem.extensions.coingeckoId]?.usd_24h_change || '';

          portfolio.push({
              mint: mint,
              balance: sol,
              price,
              value: price * sol,
              tokenInfo: tokenInfo,
              usd_24h_change: usd_24h_change
          });
      }

      portfolio = portfolio.sort(function(a, b) {
          return b.value - a.value;
      });
      
      setSuccess(true);
      
      setGrapeTicker({
        grapeTokenReference
      })
      setSolTicker({
        solTokenReference
      })
      
      setPorfolioBalances({
          portfolio,
          //staked,
          collectibles
      });

      const { isAvailable, url } = await getProfilePicture(connection, new PublicKey(session.publicKey), {resize:'256'});
      setProfilePicutureUrl(url);
      setHasProfilePicture(isAvailable);

      //console.log("2. PORTFOLIO: "+JSON.stringify(portfolio));
      //console.log("2. STAKED: "+JSON.stringify(staked));
      //console.log("2. COLLECTIBLES: "+JSON.stringify(collectibles));

      setLoading(false);
      
    } else{
      return (
        <Grid item xs={12} md={8} lg={9}>
          <Paper class="grape-paper-background">
            <Paper
              class="grape-paper"
              sx={{
                p: 2,
                display: 'flex',
                flexDirection: 'column',
                minHeight: 240,
              }}
            >
              <Box sx={{ p:1, display: 'flex', alignItems: 'center' }}>
                <Skeleton />
              </Box>
            </Paper>
          </Paper>
        </Grid>
      );
    }
  };

  //Get Balances
  let total = 0;
  let portfolioTotal = 0; 
  let portfolioChange = 0; 
  let portfolioPercentageChange = 0; 
  let stakedTotal = 0;

  const handleDeleteChange = () => {

  };

  if(!portfolioPositions){
    //console.log("Getting balances...");
    if (session.publicKey)
      getBalances();
    return (
      <React.Fragment>
        <Grid item xs={12} md={8} lg={9}>
          <Paper class="grape-paper-background">
            <Paper
              class="grape-paper"
              sx={{
                p: 2,
                display: 'flex',
                flexDirection: 'column',
                minHeight: 240,
              }}
            >
              <Box sx={{ p:1, width: "100%" }}>
                <Skeleton
                  animation="wave"
                  width="25%"
                />
                <Skeleton 
                  animation="wave"
                  width="100%" 
                  sx={{ mt: 1 }} />
                <Skeleton 
                  animation="wave"
                  width="100%" 
                  sx={{ mt: 0 }} />
                <Skeleton 
                  animation="wave"
                  width="100%" 
                  sx={{ mt: 0 }} />
              </Box>
            </Paper>
          </Paper>
        </Grid>
        <Grid item xs={12} md={4} lg={3}>
          <Paper class="grape-paper-background">
            <Paper
              class="grape-paper"
              sx={{
                p: 2,
                display: 'flex',
                flexDirection: 'column',
                minHeight: 240,
              }}
            >
              <Box sx={{ p:1, width: "100%" }}>
                <Skeleton 
                  animation="wave" 
                  width="20%" />
                <Skeleton 
                  animation="wave"
                  width="100%" 
                  sx={{ mt: 1 }} />
                <Skeleton 
                  animation="wave"
                  width="100%" 
                  sx={{ mt: 0 }} />
                <Skeleton 
                  animation="wave"
                  width="100%" 
                  sx={{ mt: 0 }} />
                </Box>
            </Paper>

          </Paper>
        </Grid>
      </React.Fragment>
    );
  }else{   
    portfolioTotal = portfolioPositions.portfolio.reduce((acc, token) => {
      return acc + token.value;
    }, 0);

    portfolioChange = portfolioPositions.portfolio.reduce((acc, token) => {
      // change for the token value in %
      // see what the change was
      //let change = token.usd_24h_change; // 
      let change_amount = token.value * (1*token.usd_24h_change/100);// calculate change
      
      return acc + change_amount;
    }, 0);

    // let percentage_change = change_amount/token.value;
    portfolioPercentageChange = portfolioChange / portfolioTotal * 100;

    total = portfolioTotal;
  }
  
  return (
      <React.Fragment>
        
          <Grid item xs={12} md={8} lg={9}>
              <Paper class="grape-paper-background">
                <Box class="grape-paper">
                  <Box sx={{ display: 'flex', alignItems: 'left' }}>
                    <Box class="grape-dashboard-component-header" sx={{ m: 0, position: 'relative' }}>
                      <Grid
                        container
                        direction="row"
                      >
                        <Grid item>
                          <Box class="grape-dashboard-component-header" sx={{ m: 0, position: 'relative' }}>
                            <Typography gutterBottom variant="h6" component="div" sx={{ m: 0, position: 'relative'}}>
                              PORTFOLIO
                            </Typography>
                          </Box>
                        </Grid>
                        <Grid item>
                            <Box sx={{ ml: 1, position: 'relative' }}>
                              <Typography component="div" variant="caption">
                                <Button sx={{borderRadius:'24px',p:0.5,minWidth:0}} size="small" variant="text" value="Refresh" onClick={getBalances} disabled={loading}>
                                  <CachedIcon />
                                </Button>
                                {loading && (
                                  <CircularProgress 
                                    size={24} 
                                    color="inherit"
                                    sx={{
                                      position: 'absolute',
                                      top: '50%',
                                      left: '50%',
                                      marginTop: '-12px',
                                      marginLeft: '-12px',
                                    }}/>
                                )}
                                </Typography>
                              </Box>
                          </Grid> 
                        </Grid>
                      </Box>
                    </Box>
                    <PortfolioTable balances={portfolioPositions.portfolio}/>
                </Box>
              </Paper>
          </Grid>
          
          <Grid item xs={12} md={4} lg={3}>
            <Paper class="grape-paper-background">
              <Box
                class="grape-paper"
              >
              
              <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
                <Tabs value={value} onChange={handleTabChange} aria-label="basic tabs example">
                  <Tab icon={<GrapeIcon />} aria-label="Grape" {...a11yProps(0)} />
                  <Tab icon={<SolIcon />} aria-label="Solana" {...a11yProps(1)} />
                </Tabs>
              </Box>
              <TabPanel value={value} index={0}>
                <Summary title="TICKER" token={'grape'} subtitle={<GrapeIcon fontSize='12px' />} showtimestamp={true} tstamp={tstamp} calltoaction="" hasrefresh={true} swaptoken={'grape'} portfolioPositions={portfolioPositions} tokenMap={tokenMap}>
                  <Grid container direction="row" alignItems="center" justifyContent="center">
                    <Grid item>
                      $<PretifyCommaNumber number={parseFloat(grapeTicker.grapeTokenReference).toFixed(3)} />
                    </Grid>
                  </Grid>
                </Summary>
              </TabPanel>
              <TabPanel value={value} index={1}>
                <Summary title="TICKER" token={'sol'} subtitle={<SolCurrencyIcon fontSize='12px' />} showtimestamp={true} tstamp={tstamp} calltoaction="" hasrefresh={true}>
                  <Grid container direction="row" alignItems="center" justifyContent="center">
                    <Grid item>
                      $<PretifyCommaNumber number={parseFloat(solTicker.solTokenReference).toFixed(2)} />
                    </Grid>
                  </Grid>
                </Summary>
              </TabPanel>
          
                {(+portfolioTotal > 0) && 
                  <React.Fragment>
                    <Divider sx={{mt:2}} />
                    <Box sx={{mt:2}}>
                      <Summary title="WALLET" subtitle="SUMMARY" showtimestamp={false} calltoaction="" hasrefresh={false}>
                        $<PretifyCommaNumber number={portfolioTotal.toFixed(2)} />
                        {portfolioChange < 0 ?
                          <>
                            <Typography variant="subtitle2" sx={{ flex: 1, color:"#f00", textAlign:"center"}}>
                                <Tooltip title={`24h change $${portfolioChange.toFixed(2)}`}> 
                                  <Chip color="error" deleteIcon={<ArrowDownwardIcon />} onDelete={handleDeleteChange} label={`${portfolioPercentageChange.toFixed(2)}%`} size="small" variant="outlined"/>
                                </Tooltip>
                            </Typography>
                          </>
                        :
                          <>
                            <Typography color="text.secondary" variant="subtitle2" sx={{ flex: 1, textAlign:"center" }}>
                              <Tooltip title={`24h change $${portfolioChange.toFixed(2)}`}>  
                                <Chip color="success" deleteIcon={<ArrowUpwardIcon />} onDelete={handleDeleteChange} label={`${portfolioPercentageChange.toFixed(2)}%`} size="small" variant="outlined"/>
                              </Tooltip>
                            </Typography>
                          </>
                        }
                      </Summary>
                      
                    </Box>
                    <Summary title="" subtitle="" showtimestamp={false} calltoaction="" hasrefresh={false}>
                        {(portfolioPositions.collectibles && portfolioPositions.collectibles.length > 0) &&
                            <Grid item sx={{textAlign:"center"}}>
                                <Button
                                  component="a" href={`https://grape.art/profile?pkey=${session?.publicKey}`} target="_blank"
                                  variant="outlined" 
                                  title="View Collection"
                                  size="small"
                                  >
                                  
                                  {(hasProfilePicture && profilePictureUrl) ?
                                    <Avatar sx={{ width: 24, height: 24, mr:1 }} alt="Profile" src={profilePictureUrl} />
                                  :
                                    <AccountCircleIcon sx={{mr:1}}/>
                                  }
                                  
                                  {portfolioPositions.collectibles.length} {portfolioPositions.collectibles.length > 1 ? 'Collectibles' : 'Collectible'}
                                </Button>
                              
                            </Grid>
                          }
                      </Summary>
                  </React.Fragment>
                }
                  {/* (balances.staked && balances.staked.length) &&*/}

                { /*(stakedTotal > 0) &&
                  <Box sx={{mt:2}}>
                    <Summary title="STAKED" subtitle="SUMMARY" showtimestamp={false} calltoaction="" hasrefresh={false}>{`$${+stakedTotal.toFixed(2)}`}</Summary>
                  </Box>
                */  }
                
              </Box>
            </Paper>
          </Grid>

        <FarmsView portfolioPositions={portfolioPositions} tokenMap={tokenMap} initPortfolio={initPortfolio} initCGPriceData={initCGPriceData} initNewPriceData={initNewPriceData} />

      </React.Fragment>
  );
};
