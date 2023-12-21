import * as React from "react";
import { useEffect, useState } from "react";
import { TokenListProvider, TokenInfo } from '@solana/spl-token-registry';

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
  Badge,
} from '@mui/material/'

import PropTypes from 'prop-types';

import { useSession } from "../../contexts/session";
import Summary from '../Summary/Summary';
import TwitterFeedComponent from '../Feed/TwitterFeed';
import FarmsTable from './FarmsTable';
import { nu64, struct, u8, blob } from 'buffer-layout';
import { publicKey, u128, u64 } from '@project-serum/borsh'
import { TokenAmount, lt } from '../../utils/token/safe-math';
import { getFarmByPoolId } from '../../utils/token/farms';
import BigNumber from 'bignumber.js'

import { RPC_ENDPOINT, RAYDIUM_LOGO } from '../../components/Tools/constants';
//import { useTheme } from '@mui/material/styles';
import { Connection, Keypair } from "@solana/web3.js";
//import { getOrca, OrcaPoolConfig, OrcaU64 } from "@orca-so/sdk";
import {PublicKey} from '@solana/web3.js'
import { PretifyCommaNumber } from '../../components/Tools/PretifyCommaNumber';

import ArrowUpwardIcon from '@mui/icons-material/ArrowUpward';
import ArrowDownwardIcon from '@mui/icons-material/ArrowDownward';
import ImageIcon from '@mui/icons-material/Image';
import CircularProgress from '@mui/material/CircularProgress';
import RefreshIcon from '@mui/icons-material/Refresh';
import GrapeIcon from '../../components/StaticIcons/GrapeIcon';
import SolIcon from '../../components/StaticIcons/SolIcon';
import { dark } from "@mui/material/styles/createPalette";
import { lookupService } from "dns";

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

export const FarmsView = (props) => {
  const [initPortfolio, setInitPortfolio] = useState(props.initPortfolio);
  const [initCGPriceData, setInitCGPriceData] = useState(props.initCGPriceData);
  const [initNewPriceData, setInitNewPriceData] = useState(props.initNewPriceData);
  
  const [portfolioPositions, setPorfolioBalances] = useState(props.porftolioPositions);
  const [initTokenMap, setInitTokenMap] = useState(props.tokenMap);
  const { session, setSession } = useSession();
  const [loading, setLoading] = React.useState(false);
  
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
      
      //const response = await fetch("https://solana-api.projectserum.com/", {
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

    const response = await fetch(RPC_ENDPOINT, {
    //const response = await fetch("https://solana-api.projectserum.com/", {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
    });

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
    //const response = await fetch("https://solana-api.projectserum.com/", {
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
      
      setLoading(true);
      
      let portfolio = initPortfolio;
      let cgPriceData = initCGPriceData; 
      let newPriceData = initNewPriceData;
      let tokenMap = initTokenMap;
      let [staked, sol, additionalFarmPools, pairsDataRaydium] = await Promise.all([fetchStakedRaydium(), fetchSOLBalance(), fetchAdditionalFarmPools(), fetchPairsRaydium()]);
      
      // we need to now first get portfolio 
      // then load a skeleton (without positions)
      // then load positions from fetched data from cg or other source

      let legacyPriceData = [];
      //let [newPriceData] = [null];
      
      let other_stakes = [];
      
      let priceData = [];

      if (!newPriceData){
        [legacyPriceData] = await Promise.all([fetchLegacyPriceList()]);
        //[newPriceData] = await Promise.all([fetchCoinGeckoPriceList()]);
        
        //const newPriceDataResponse = await newPriceData;
        //   console.log("DATA: "+JSON.stringify(newPriceData.prices));
        
        if (!legacyPriceData)
          console.log("NO DATA");
      }
      // check which data we have loaded so we can parse accordingly
      // TULIP POOL: 
      // ?? fhA1P91Hk3K689GJcvP9pEAjPC2RmeLdyPZzqSyBwsh balance = 1 ??
      // ?? EorFh8siFyLF1QTZ7cCXQaPGqyo7eb4SAgKtRH8Jcxjd??
      // ?? A8ZYmnZ1vwxUa4wpJVUaJgegsuTEz5TKy5CiJXffvmpt ??

      //console.log("Portfolio HERE: "+JSON.stringify(portfolio));
      
      portfolio = portfolio.map((token) => {
        let mint = token.account.data.parsed.info.mint;
        let balance = token.account.data.parsed.info.tokenAmount.uiAmount;
        let tmapitem = mint && tokenMap.get(mint);
        let price = (tmapitem && tmapitem.extensions?.coingeckoId) && cgPriceData[tmapitem.extensions.coingeckoId]?.usd || 0;
        let usd_24h_change = (tmapitem && tmapitem.extensions?.coingeckoId) && cgPriceData[tmapitem.extensions.coingeckoId]?.usd_24h_change || '';

        // tokenInfo.extensions.coingeckoId

        if (tmapitem){  
          if (tmapitem.extensions?.coingeckoId){

            //try{
              //console.log("tmapitem: "+JSON.stringify(tmapitem));
              //console.log("pushing ("+tmapitem.extensions.coingeckoId+"): " + JSON.stringify(cgPriceData[tmapitem.extensions.coingeckoId]?.usd));
              //console.log("FOUND: "+psymbol);
              // IMPORTANT ADD CHECK TO GET PRICE FROM CG
              priceData.push({
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
        
        if ((balance > 0)&&
            (+token.account.data.parsed.info.tokenAmount.decimals != 0)){

          Object.keys(newPriceData.farms).forEach(function(key) {
            if (newPriceData.farms[key].additional?.farmTokenMint){ // this is exclusively for Orca:
              if (newPriceData.farms[key].additional?.farmTokenMint == token.account.data.parsed.info.mint){ 
                const farmPlatform = "Orca Aquafarm";//newPriceData.farms[key].platform;
                const farmPlatformLogo = 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/97q89hnoKwqcynvwXcj83YqfqUBuCm4A8f2zHeV6bfZg/logo.svg';
                
                // get assets
                let assets = [];
                
                newPriceData.farms[key].lp.assets.map((asset) => {
                  let atmapitem = asset.mint && tokenMap.get(asset.mint);
                  assets.push({
                    name: atmapitem && atmapitem.symbol || 'Unknown',//newPriceData.tokens[asset.mint].symbol,
                    logo: atmapitem && atmapitem.logoURI || '', //newPriceData.tokens[asset.mint].logoURI
                  })
                });
                
                //console.log("Found: "+JSON.stringify(newPriceData.farms[key]));
                other_stakes.push({
                  balance: balance,
                  pendingReward: 0,
                  tokenInfo: null,//mint && tokenMap.get(mint),
                  lpprice: 0,
                  apr: newPriceData.farms[key]?.apr || '',
                  value: balance*(+newPriceData.farms[key]?.lp?.price || 0),
                  farmInfo: assets,
                  farmName: farmPlatform,
                  farmPoolId: token.account.data.parsed.info.mint,
                  stakedInfo: null,
                  farmLogoURI: farmPlatformLogo,
                  farmPendingReward: 0
                });
                  
                
              }
            } else if (newPriceData.farms[key].lp?.mint){ // this is exclusively for SolFarm:
              
              /*
              if (newPriceData.farms[key].platform == "solfarm"){
                if (newPriceData.farms[key].mint == token.account.data.parsed.info.mint){ 
                  console.log("Platform: "+newPriceData.farms[key]?.platform);
                  console.log("Mint: "+token.account.data.parsed.info.mint);
                }
              }
              */
              
              if (newPriceData.farms[key].lp?.mint == token.account.data.parsed.info.mint){ 
                
                

                if (newPriceData.farms[key]?.platform == "raydium"){
                } else if (newPriceData.farms[key].platform == "solfarm"){
                  
                  console.log("Solfarm::: "+JSON.stringify(newPriceData.farms[key]));
                  
                  const farmPlatform = "Tulip/solFarm";//newPriceData.farms[key].platform;
                  const farmPlatformLogo = 'https://tulip.garden/static/media/tulip.be0a265d.svg';

                  // get assets
                  let assets = [];
                  newPriceData.farms[key].lp.assets.map((asset) => {
                    let atmapitem = asset.mint && tokenMap.get(asset.mint);
                    assets.push({
                      name: atmapitem && atmapitem.symbol || 'Unknown',//newPriceData.tokens[asset.mint].symbol,
                      logo: atmapitem && atmapitem.logoURI || '', //newPriceData.tokens[asset.mint].logoURI
                    })
                  });
                
                  let rassets = '';
                  let y = 0;
                  if (newPriceData.farms[key]?.rewardAssets) {
                    newPriceData.farms[key].rewardAssets.map((rasset) => {
                      if (y>0)
                        rassets+= '-';
                      rassets+= newPriceData.tokens[rasset.mint].symbol;
                      y++;
                    });
                  }

                  if ((y == 0)&&(newPriceData.farms[key].lp.value>0)){ 
                    //lp_balance = newPriceData.farms[key].lp.amount;
                    /*
                    other_stakes.push({
                        balance: balance,
                        pendingReward: 0,
                        tokenInfo: null,//mint && tokenMap.get(mint),
                        lpprice: newPriceData.farms[key].lp.price,
                        value: price,
                        farmInfo: assets,
                        //farmInfo: {name:"TULIP"},
                        farmName: farmPlatform,
                        farmPoolId: token.account.data.parsed.info.mint,
                        stakedInfo: null,
                        farmLogoURI: farmPlatformLogo,
                        farmPendingReward: 0
                    });
                    */
                    
                  }
                  
                }
              }
            }
          });
        }

        return {
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
        return (token.balance > 0) && (token.price > 0) && typeof token.balance !== "undefined";
      });
      
      portfolio = portfolio.sort(function(a, b) {
          return b.value - a.value;
      });

      staked = staked && staked.map((stakeAccountInfo) => {
          const { data } = stakeAccountInfo.accountInfo
          const userStakeInfo = USER_STAKE_INFO_ACCOUNT_LAYOUT.decode(data)
          const poolId = userStakeInfo.poolId.toBase58()
          const stakerOwner = userStakeInfo.stakerOwner.toBase58()
          const farm = getFarmByPoolId(poolId);

          //console.log("Pool:" +poolId);

          if(!farm) {
            return {
              balance: 0
            }
          }
          
          const farmPlatform = 'Raydium';

          const pair = pairsDataRaydium.find(pair => {
            return pair.name === farm.name
          });
          
          let farmshift = farm.lp.coin.decimals;
          let shift = -1*farmshift;

          let balance = new BigNumber(+userStakeInfo.depositBalance);
          balance = balance.shiftedBy(shift);
          
          let pendingReward = new BigNumber(+userStakeInfo.rewardDebt);
          pendingReward = pendingReward.shiftedBy(shift);

          let invalid_balance = new TokenAmount(userStakeInfo.depositBalance.toNumber(), 6);
          invalid_balance = parseFloat(invalid_balance.format());

          let invalid_pendingReward = new TokenAmount(userStakeInfo.rewardDebt.toNumber(), 6);
          invalid_pendingReward = parseFloat(invalid_pendingReward.format());

          //farmData = newPriceData.farms.find(pair => {
          //const found = newPriceData.farms.find(element => element == poolId);
          //console.log("FOUND: "+JSON.stringify(found));

          let farmValue = pair.price * balance;
          let farmApr = 0;

          let assets = [];

          Object.keys(newPriceData.farms).forEach(function(key) {
            if (newPriceData.farms[key]?.address){
              if (newPriceData.farms[key]?.address == poolId){ 
                
                newPriceData.farms[key].lp.assets.map((asset) => {
                  let atmapitem = asset.mint && tokenMap.get(asset.mint);
                  assets.push({
                    name: atmapitem && atmapitem.symbol || 'Unknown',//newPriceData.tokens[asset.mint].symbol,
                    logo: atmapitem && atmapitem.logoURI || '', //newPriceData.tokens[asset.mint].logoURI
                  })
                });
                
                farmValue = balance*(+newPriceData.farms[key]?.lp?.price || 0);
                farmApr = newPriceData.farms[key]?.apr || 0;
                
              }
            }
          });

          //if (farmPlaform)
          //  console.log("farmPlaform: "+(farmPlatform||"null"));
          
          return {
              balance,
              pendingReward,
              tokenInfo: null,//mint && tokenMap.get(mint),
              lpprice : pair.price,
              value : farmValue,
              farmInfo: assets,
              apr: farmApr,
              farmName: farmPlatform||null,
              farmPoolId: poolId,
              stakedInfo: data,
              farmLogoURI: RAYDIUM_LOGO,
              farmPendingReward: 0
          }
      }).filter((token) => {
          return token.balance > 0;
      });
      
      if (staked){
        {other_stakes != null && 
          staked.push(...other_stakes);
        }
      }

      setPorfolioBalances({
          staked
      });
      
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
              <Box sx={{ display: 'flex', alignItems: 'center' }}>
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
        <Grid item xs={12} md={12} lg={12}>
          <Paper class="grape-paper-background">
            <Paper
              class="grape-paper"
              sx={{
                p: 2,
                display: 'flex',
                flexDirection: 'column',
              }}
            >
              <Box sx={{ width: "100%", p:1 }}>
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
    
    stakedTotal = portfolioPositions.staked && portfolioPositions.staked.reduce((acc, token) => {
        return acc + token.value;
    }, 0);

    total = portfolioTotal + stakedTotal;
  }
  
  return (
      <React.Fragment>
        
        {(portfolioPositions.staked && portfolioPositions.staked.length) ? 
        <React.Fragment>
          {/*
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
                
                
              </Paper>
            </Paper>
          </Grid>
          */}
          <Grid item xs={12} md={12} lg={12}>
            <Paper class="grape-paper-background">
              <Box class="grape-paper">
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <Box class="grape-dashboard-component-header" sx={{ m: 0, position: 'relative' }}>
                    <Typography gutterBottom variant="h6" component="div" sx={{ m: 0, position: 'relative'}}>
                      YIELD FARMING
                    </Typography>
                  </Box>
                </Box>
                <FarmsTable balances={portfolioPositions.staked} isFarm={true}/>
              </Box>
            </Paper>
          </Grid>
        </React.Fragment> : <div/>}
        
      </React.Fragment>
  );
};
