import * as React from 'react';
import {
    Alert,
    Typography,
    Box,
    Button,
    Grid,
    Paper,
    Step,
    Stepper,
    StepLabel,
    TextField,
    InputLabel,
    FormControl,
    MenuItem,
    Select,
 } from '@mui/material';


import CheckIcon from '@mui/icons-material/Check';

import * as anchor from "@project-serum/anchor";
import { Provider, AnchorProvider } from "@project-serum/anchor";

import JupiterSwap from "../JupiterSwap/JupiterSwap";
import StrataSwap from "../StrataSwap/StrataSwap";
import { JupiterProvider, useJupiter } from "@jup-ag/react-hook";
import { useWallet } from '@solana/wallet-adapter-react';

import { SplTokenBonding } from "@strata-foundation/spl-token-bonding";
import { SplTokenCollective } from "@strata-foundation/spl-token-collective";
import { getAssociatedAccountBalance, SplTokenMetadata } from "@strata-foundation/spl-utils";

import { getRealm, getRealms, getAllProposals, getGovernance, getTokenOwnerRecordsByOwner, getTokenOwnerRecord, getRealmConfigAddress, getGovernanceAccount, getAccountTypes, GovernanceAccountType, tryGetRealmConfig  } from '@solana/spl-governance';
import {ENV, TokenInfo, TokenListProvider} from '@solana/spl-token-registry';
import { TokenAmount, lt } from '../../utils/token/safe-math';
import { PublicKey, Connection } from '@solana/web3.js';

import { 
    GRAPE_RPC_ENDPOINT, 
    GOVERNANCE_RPC_ENDPOINT,
    TX_RPC_ENDPOINT } from '../../components/Tools/constants';

const GAN_REQUIREMENT = 1;
const GRAPE_TO_GAN_REQUIRED = 10600;
const GAN_TOKEN = '4BF5sVW5wRR56cy9XR8NFDQGDy5oaNEFrCHMuwA9sBPd';
//const GAN_TOKEN = '8upjSpvjcdpuzhfR1zriwg5NXkwDruejqNE9WNbPRtyA';
const GRAPE_TOKEN = '8upjSpvjcdpuzhfR1zriwg5NXkwDruejqNE9WNbPRtyA';
const USDC_TOKEN = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const SOL_TOKEN = 'So11111111111111111111111111111111111111112';

 const steps = [
    'Get Grape',
    'Get GAN',
    'Associate Discord',
  ];

 export default function HorizontalLabelPositionBelowStepper(props:any) {
    const refresh = props.refresh;
    const tokenMap = props.tokenMap;
    const grapePosition = props.grapePosition;
    const ganPosition = props.ganPosition;
    const ganGovernancePosition = props.ganGovernancePosition;
    const portfolioPositions = props.portfolioPositions;
    const [verificationType, setVerificationType] = React.useState('');
    const [disabled, setDisabled] = React.useState(false);
    const [totalGan, setTotalGan] = React.useState(0);
    const [activeStep, setActiveStep] = React.useState(0);
    const [completed, setCompleted] = React.useState<{
        [k: number]: boolean;
    }>({});

    const handleVerificationTypeChange = (event) => {
        setVerificationType(event.target.value);
    };

    const totalSteps = () => {
        return steps.length;
      };
    
    const completedSteps = () => {
        return Object.keys(completed).length;
    };

    const isLastStep = () => {
        return activeStep === totalSteps() - 1;
    };

    const allStepsCompleted = () => {
        return completedSteps() === totalSteps();
    };

    const handleBack = () => {
        setActiveStep((prevActiveStep) => prevActiveStep - 1);
      };
    
    const handleStep = (step: number) => () => {
        setActiveStep(step);
    };

    const handleNext = () => {
        const newActiveStep =
          isLastStep() && !allStepsCompleted()
            ? // It's the last step, but not all steps have been completed,
              // find the first step that has been completed
              steps.findIndex((step, i) => !(i in completed))
            : activeStep + 1;
        setActiveStep(newActiveStep);
        handleStep(newActiveStep)
    };
    
    const handleComplete = () => {
        const newCompleted = completed;
        newCompleted[activeStep] = true;
        setCompleted(newCompleted);
        handleNext();
    };

    const handleReset = () => {
        setActiveStep(0);
        setCompleted({});
    };

    React.useEffect(() => {
        if (activeStep){
            if (activeStep+1 === 2){
                if (!ganPosition && !ganGovernancePosition){
                    // check balance
                    setDisabled(true);
                } else{
                    let aggregate = 0;
                    if (ganPosition){
                        aggregate += Number(new TokenAmount(ganPosition.tokenAmount.amount, ganPosition.tokenAmount.decimals).format().replace(/[^0-9.-]+/g,""));
                    }
                    if (ganGovernancePosition){
                        aggregate += ganGovernancePosition;
                    }

                    setTotalGan(aggregate);

                    if (aggregate < GAN_REQUIREMENT){
                        setDisabled(true);
                    }
                }
            } else{
                setDisabled(false);
            }
        } else{
            setDisabled(false);
        }
        console.log("tokenMap "+JSON.stringify(tokenMap))
      }, [activeStep]);

    return (
      <Box sx={{ width: '100%' }}>
        <Stepper activeStep={activeStep} alternativeLabel>
          {steps.map((label,key) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>
        
        <div>
        {allStepsCompleted() ? (
          <React.Fragment>
            <Typography sx={{ mt: 2, mb: 1 }}>
              All steps completed - you&apos;re finished
            </Typography>
            <Box sx={{ display: 'flex', flexDirection: 'row', pt: 2 }}>
              <Box sx={{ flex: '1 1 auto' }} />
              <Button onClick={handleReset}>Reset</Button>
            </Box>
          </React.Fragment>
        ) : (
          <React.Fragment>
            
            {activeStep+1 === 1 &&
                <Typography sx={{ mt: 2, mb: 1 }}>
                    {/*Step {activeStep + 1}<br/><br/>*/}

                    <Grid container
                        textAlign='center'
                        alignContent='center'
                        direction='column'
                        sx={{mt:2}}
                    >
                        <Grid item 
                            justifyContent='left'
                            alignContent='left'
                            textAlign='left'
                            sx={{m:1}}>
                            
                            {grapePosition && 
                                <> 
                                   {+(Number(new TokenAmount(grapePosition.tokenAmount.amount, grapePosition.tokenAmount.decimals).fixed())) < GRAPE_TO_GAN_REQUIRED ?
                                        <Alert severity="error" sx={{borderRadius:'17px',backgroundColor:'rgba(0,0,0,0.5)'}}>{Number(new TokenAmount(grapePosition.tokenAmount.amount, grapePosition.tokenAmount.decimals).format())} {tokenMap.get(grapePosition.mint)?.name || grapePosition.mint} Tokens held in Wallet<br/>You need approximately {GRAPE_TO_GAN_REQUIRED - +(Number(new TokenAmount(grapePosition.tokenAmount.amount, grapePosition.tokenAmount.decimals).fixed()))} more Grape for 1 GAN</Alert>
                                    :
                                        <Alert severity="success" sx={{borderRadius:'17px',backgroundColor:'rgba(0,0,0,0.5)'}}>{Number(new TokenAmount(grapePosition.tokenAmount.amount, grapePosition.tokenAmount.decimals).format())} {tokenMap.get(grapePosition.mint)?.name || grapePosition.mint} Tokens held in Wallet</Alert>
                                    }
                                </>
                            }
                        </Grid>
                        <Grid item 
                            justifyContent='left'
                            alignContent='left'
                            textAlign='left'
                            sx={{m:1}}>

                            {totalGan ? 
                                <>
                                    {totalGan > GAN_REQUIREMENT ?
                                        <Alert severity="success" sx={{borderRadius:'17px',backgroundColor:'rgba(0,0,0,0.5)'}}>{totalGan} GAN Tokens held in Wallet/Governance</Alert>
                                    :
                                        <Alert severity="error" sx={{borderRadius:'17px',backgroundColor:'rgba(0,0,0,0.5)',m:1}}>At least {GAN_REQUIREMENT} GAN required to proceed, you have {Number(new TokenAmount(ganPosition.tokenAmount.amount, ganPosition.tokenAmount.decimals).format())} {tokenMap.get(ganPosition.mint)?.name || ganPosition.mint}, GAN Token is required to connect a Discord server with Grape<br />You can swap Grape for GAN in the next step<br/>*approximately {GRAPE_TO_GAN_REQUIRED} Grape is required for 1 GAN</Alert>
                                    }

                                </>
                            :
                            <>
                                <Alert severity="warning" sx={{borderRadius:'17px',backgroundColor:'rgba(0,0,0,0.5)'}}>At least {GAN_REQUIREMENT} GAN Token is required to connect a Discord server with Grape<br />You can swap Grape for GAN in the next step<br/>*approximately {GRAPE_TO_GAN_REQUIRED} Grape is required for 1 GAN
                                    <br/><br/>
                                    <Button
                                        href='https://discord.gg/rq22BEkD'
                                        target='_blank'
                                    >
                                    For Help Click Here
                                    </Button>
                                </Alert>
                            </>
                            }
                        </Grid>

                        <Grid item sx={{m:1}}>
                            <Typography variant='h5'>
                                Quickly swap and get Grape<br/>
                            </Typography>
                        </Grid>

                        <Grid item>
                            {portfolioPositions && tokenMap &&
                                <>
                                    <JupiterSwap swapfrom={SOL_TOKEN} swapto={GRAPE_TOKEN} portfolioPositions={portfolioPositions} tokenMap={tokenMap} />
                                    <br />
                                    <JupiterSwap swapfrom={USDC_TOKEN} swapto={GRAPE_TOKEN} portfolioPositions={portfolioPositions} tokenMap={tokenMap} />
                                </>
                            }
                        </Grid>
                    </Grid>
                </Typography>
            }

            {activeStep+1 === 2 &&
                <Typography sx={{ mt: 2, mb: 1 }}>
                    {/*Step {activeStep + 1}<br/><br/>*/}

                    <Grid container
                        textAlign='center'
                        alignContent='center'
                        direction='column'
                        sx={{mt:2}}
                    >
                        <Grid item 
                            justifyContent='left'
                            alignContent='left'
                            textAlign='left'
                            sx={{m:1}}>
                            <Typography variant='h5'>
                                GAN is required for setting up a server with Grape
                            </Typography>
                            <Typography variant='caption'>
                                GAN enabled servers have:
                                    <ul>
                                        <li>dedicated discord channel support</li>
                                        <li>quick role removals</li>
                                        <li>multi-wallet support</li>
                                        <li>administrator verification settings for managing your gated communities</li>
                                        <li>dedicated NFT community tools</li>
                                    </ul>
                            </Typography>
                        </Grid>
                        
                        {totalGan ? 
                            <>
                                {totalGan > GAN_REQUIREMENT ?
                                    <Alert severity="success" sx={{borderRadius:'17px',backgroundColor:'rgba(0,0,0,0.5)'}}>{totalGan} GAN Tokens held in Wallet/Governance</Alert>
                                :
                                    <Alert severity="error" sx={{borderRadius:'17px',backgroundColor:'rgba(0,0,0,0.5)',m:1}}>At least {GAN_REQUIREMENT} GAN required to proceed, you have {Number(new TokenAmount(ganPosition.tokenAmount.amount, ganPosition.tokenAmount.decimals).format())} {tokenMap.get(ganPosition.mint)?.name || ganPosition.mint}</Alert>
                                }

                            </>
                        :
                        <>
                            <Alert severity="warning" sx={{borderRadius:'17px',backgroundColor:'rgba(0,0,0,0.5)'}}>At least {GAN_REQUIREMENT} GAN Token is required to continue</Alert>
                        </>
                        }

                        <Grid item xs={12} sx={{mt:2}}>
                            <StrataSwap swapfrom={GRAPE_TOKEN} swapto={GAN_TOKEN} swapamount={1} refresh={refresh} />
                        </Grid>

                    </Grid>
                </Typography>
            }
            
            {activeStep+1 === 3 &&
                <Typography sx={{ mt: 2, mb: 1 }}>
                    {/*Step {activeStep + 1}<br/><br/>*/}
                    <Grid container
                        textAlign='center'
                        alignContent='center'
                        direction='column'
                        sx={{mt:2}}
                    >
                        <Grid item xs={12} sx={{mt:2}}>
                            <Typography>
                                Associate your discord
                            </Typography>


                            <Alert severity="warning" sx={{borderRadius:'17px',backgroundColor:'rgba(0,0,0,0.5)'}}>Discord autoconnect coming soon, please send us the wallet publicKey and your discord server link you have purchased your GAN for so we can associate your discord, please visit 
                            <br/><br/><Button
                                    href='https://discord.gg/rq22BEkD'
                                    target='_blank'
                                >
                                https://discord.gg/rq22BEkD
                                </Button>
                            </Alert>

                            <FormControl fullWidth sx={{m:1}}>
                                <TextField id="outlined-basic" label="Server ID" variant="outlined" />
                            </FormControl>

                            <FormControl fullWidth sx={{m:1}}>
                                <InputLabel id="demo-simple-select-label">Verification Type</InputLabel>
                                <Select
                                    labelId="demo-simple-select-label"
                                    id="demo-simple-select"
                                    value={verificationType}
                                    label="Verification Type"
                                    onChange={handleVerificationTypeChange}
                                >
                                    <MenuItem value={10}>Token</MenuItem>
                                    <MenuItem value={20}>NFT</MenuItem>
                                    <MenuItem value={30}>Token &amp; Governance</MenuItem>
                                    <MenuItem value={40}>Staking</MenuItem>
                                </Select>
                            </FormControl>

                            <FormControl fullWidth sx={{m:1}}>
                                <TextField id="outlined-basic" label="Mint" variant="outlined" />
                            </FormControl>

                        </Grid>
                    </Grid>
                </Typography>
            }
            
            <Box sx={{ display: 'flex', flexDirection: 'row', pt: 2 }}>
              <Button
                color="inherit"
                disabled={activeStep === 0}
                onClick={handleBack}
                sx={{ mr: 1 }}
              >
                Back
              </Button>
              <Box sx={{ flex: '1 1 auto' }} />
              <Button 
                onClick={handleNext} 
                disabled={disabled}
                sx={{ mr: 1 }}
            >
                Next
              </Button>
              {activeStep !== steps.length &&
                (completed[activeStep] ? (
                  <Typography variant="caption" sx={{ display: 'inline-block' }}>
                    Step {activeStep + 1} already completed
                  </Typography>
                ) : (
                  <>
                  {/*
                  <Button onClick={handleComplete}>
                    {completedSteps() === totalSteps() - 1
                      ? 'Finish'
                      : 'Complete Step'}
                  </Button>
                    */}
                  </>
                ))}
            </Box>
          </React.Fragment>
        )}
      </div>

      </Box>
    );
  }

export function AdminView(props: any) {
    const [loadingPosition, setLoadingPosition] = React.useState(null);
    //const [tokenMap, setTokenMap] = React.useState(null);
    const [tokenMap, setTokenMap] = React.useState<Map<string,TokenInfo>>(undefined);
    const [strataTokenMetadata, setStrataTokenMedatada] = React.useState(null);
    const [loadingTokens, setLoadingTokens] = React.useState(false);
    const [loadingWallet, setLoadingWallet] = React.useState(false);
    const [loadingGovernance, setLoadingGovernance] = React.useState(false);
    const [loadingStrata, setLoadingStrata] = React.useState(false);
    const [hasGAN, setHasGAN] = React.useState(false);
    const [grapePosition, setGrapePosition] = React.useState(null);
    const [ganPosition, setGanPosition] = React.useState(null);
    const [ganGovernance, setGanGovernance] = React.useState(null);
    const [governanceRecord, setGovernanceRecord] = React.useState(null);
    const [portfolioPositions, setPortfolioPositions] = React.useState(null);
    const ticonnection = new Connection(GOVERNANCE_RPC_ENDPOINT);
    const { publicKey, disconnect } = useWallet()
    const connection = new Connection(GRAPE_RPC_ENDPOINT);
    //const provider = anchor.getProvider();
    const wallet = useWallet();
    const provider = new AnchorProvider(connection, wallet, {});

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

            if (item.account.data.parsed.info.mint === GAN_TOKEN){
                if (item.account.data.parsed.info.tokenAmount.amount > 0)
                    setGanPosition(item.account.data.parsed.info);
            }  
            
            if (item.account.data.parsed.info.mint === GRAPE_TOKEN){
                if (item.account.data.parsed.info.tokenAmount.amount > 0){
                    //console.log("found grape")
                    setGrapePosition(item.account.data.parsed.info);
                }
            }
        }
        setPortfolioPositions(resultValues)
    }

    const fetchGovernance = async () => {
        setLoadingPosition('Governance');
        const GOVERNANCE_PROGRAM_ID = 'GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw';
        const programId = new PublicKey(GOVERNANCE_PROGRAM_ID);
        
        //const rlms = await getRealms(ticonnection, programId);
        //const uTable = rlms.reduce((acc, it) => (acc[it.pubkey.toBase58()] = it, acc), {})
        //setRealms(uTable);
        
        const ownerRecordsbyOwner = await getTokenOwnerRecordsByOwner(ticonnection, programId, publicKey);

        //console.log("ownerRecordsbyOwner "+JSON.stringify(ownerRecordsbyOwner))
        const governance = new Array();
        
        let cnt = 0;
        //console.log("all uTable "+JSON.stringify(uTable))

        for (var item of ownerRecordsbyOwner){
            //const realm = uTable[item.account.realm.toBase58()];
            //console.log("realm: "+JSON.stringify(realm))
            //const name = realm.account.name;
            let votes = +item.account.governingTokenDepositAmount;
            
            let thisToken = tokenMap.get(item.account.governingTokenMint.toBase58());
            
            if (thisToken){
                if (thisToken.address === GAN_TOKEN){
                    //console.log("thisToken: "+JSON.stringify(thisToken))
                    const itemBalance = Number(new TokenAmount(+item.account.governingTokenDepositAmount, thisToken.decimals).format().replace(/[^0-9.-]+/g,""));
                    console.log("Deposited in Governance: "+itemBalance);
                    setGanGovernance(itemBalance);
                }
            } else{
                //votes = 'NFT/Council';
            }

            governance.push({
                id:cnt,
                pubkey:item.pubkey,
                realm:name,
                governingTokenMint:item.account.governingTokenMint,
                governingTokenDepositAmount:votes,
                unrelinquishedVotesCount:item.account.unrelinquishedVotesCount,
                totalVotesCount:item.account.totalVotesCount,
                relinquish:item.pubkey,
                link:item.account.realm
            });
            cnt++;
        }

        setGovernanceRecord(ownerRecordsbyOwner);
    }

    const fetchStrataMetadata = async () => {
        setLoadingStrata(true);
        setLoadingPosition('Loading Grape backed Token Metadata');
        const tokenMetadataSdk = await SplTokenMetadata.init(provider);
        /*
        const {
            image,
            metadata,
            loading: metaLoading,
          } = useTokenMetadata(tokenBonding && tokenBonding.targetMint);
        */

        setStrataTokenMedatada(tokenMetadataSdk);
        setLoadingStrata(false);
    }

    const fetchTokenPositions = async () => {
        setLoadingTokens(true);
        await fetchSolanaTokens();
        //getConnected();
        setLoadingTokens(false);
    }

    const fetchGovernancePositions = async () => {
        setLoadingGovernance(true);
        await fetchGovernance();
        setLoadingGovernance(false);
    }

    React.useEffect(() => {
        if (publicKey && tokenMap){
            fetchTokenPositions();
            fetchGovernancePositions();
            fetchStrataMetadata();
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
        <>
            {(loadingWallet || loadingTokens || loadingGovernance || loadingStrata) ?
                <></>
            :
                <>
                {tokenMap && portfolioPositions &&
                    <Grid item xs={12} sx={{mt:4}}>
                        <Paper className="grape-paper-background">
                            {portfolioPositions && tokenMap &&
                                <HorizontalLabelPositionBelowStepper tokenMap={tokenMap} portfolioPositions={portfolioPositions} grapePosition={grapePosition} ganPosition={ganPosition} ganGovernancePosition={ganGovernance} refresh={fetchTokenPositions} />
                            }
                        </Paper>
                    </Grid>
                }
                </>
            }

            <Grid item xs={12} sx={{mt:4}}>
                <Paper className="grape-paper-background">
                    <Grid 
                        className="grape-paper" 
                        container
                        spacing={0}
                        alignContent="center"
                        justifyContent="center"
                        direction="column"
                        >
                        <Grid item>
                            <Typography 
                            align="center"
                            variant="h5">
                                {(loadingWallet || loadingTokens || loadingGovernance || loadingStrata) ?
                                    <>loading {loadingPosition}...</>
                                :
                                    <>
                                        {ganPosition ?
                                            <>
                                                <Typography variant='h6'>
                                                
                                                    <Alert severity="success" sx={{borderRadius:'17px',backgroundColor:'rgba(0,0,0,0.5)',m:1}}>{Number(new TokenAmount(ganPosition.tokenAmount.amount, ganPosition.tokenAmount.decimals).format())} {tokenMap.get(ganPosition.mint)?.name || ganPosition.mint} Tokens held in Wallet</Alert>
                                
                                                    {ganGovernance && 
                                                        <>
                                                            <Alert severity="success" sx={{borderRadius:'17px',backgroundColor:'rgba(0,0,0,0.5)'}}>{ganGovernance} {tokenMap.get(ganPosition.mint)?.name || ganPosition.mint} Tokens held in Governance</Alert>
                                                        </>
                                                    }
                                                </Typography>

                                                <br/><br/>
                                                <Typography variant='caption'>
                                                    Server Verification Management coming soon...
                                                </Typography>
                                            </>
                                        :
                                            <>GAN token is required for server verification management</>
                                        }
                                    </>
                                }
                            </Typography>
                        </Grid>
                    </Grid>
                </Paper>
            </Grid>
        </>
    );
}