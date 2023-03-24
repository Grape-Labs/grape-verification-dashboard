import React, { useCallback } from 'react';
import { WalletError, WalletNotConnectedError } from '@solana/wallet-adapter-base';
import { useConnection, useWallet } from '@solana/wallet-adapter-react';
import { Signer, Connection, PublicKey, SystemProgram, Transaction, TransactionInstruction } from '@solana/web3.js';
import { TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, getOrCreateAssociatedTokenAccount, createAssociatedTokenAccountInstruction, createTransferInstruction } from "@solana/spl-token-v2";

import { RPC_CONNECTION } from '../../components/Tools/constants';
import { GRAPE_TREASURY } from '../../components/Tools/constants';
import { RegexTextField } from '../../components/Tools/RegexTextField';

import { styled } from '@mui/material/styles';

import {
  Dialog,
  Button,
  ButtonGroup,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  FormLabel,
  FormHelperText,
  MenuItem,
  InputLabel,
  Select,
  IconButton,
  Avatar,
  Grid,
  Paper,
  Typography
} from '@mui/material';


import { SelectChangeEvent } from '@mui/material/Select';
import { MakeLinkableAddress, ValidateAddress } from '../../components/Tools/WalletAddress'; // global key handling
import { useSnackbar } from 'notistack';

import CircularProgress from '@mui/material/CircularProgress';
import HelpIcon from '@mui/icons-material/Help';
import CloseIcon from '@mui/icons-material/Close';
import ArrowCircleRightIcon from '@mui/icons-material/ArrowCircleRight';
import ArrowCircleRightOutlinedIcon from '@mui/icons-material/ArrowCircleRightOutlined';

function trimAddress(addr: string) {
    if (!addr) return addr;
    let start = addr.substring(0, 8);
    let end = addr.substring(addr.length - 4);
    return `${start}...${end}`;
}

const BootstrapDialog = styled(Dialog)(({ theme }) => ({
  '& .MuDialogContent-root': {
    padding: theme.spacing(2),
  },
  '& .MuDialogActions-root': {
    padding: theme.spacing(1),
  },
}));

export interface DialogTitleProps {
  id: string;
  children?: React.ReactNode;
  onClose: () => void;
}

const BootstrapDialogTitle = (props: DialogTitleProps) => {
  const { children, onClose, ...other } = props;

  return (
    <DialogTitle sx={{ m: 0, p: 2 }} {...other}>
      {children}
      {onClose ? (
        <IconButton
          aria-label="close"
          onClick={onClose}
          sx={{
            position: 'absolute',
            right: 8,
            top: 8,
            color: (theme) => theme.palette.grey[500],
          }}
        >
          <CloseIcon />
        </IconButton>
      ) : null}
    </DialogTitle>
  );
};

export default function SendToken(props: any) {
    const [open, setOpen] = React.useState(false);
    const [amounttosend, setTokensToSend] = React.useState(0);
    const [showTokenName, setShowTokenName] = React.useState(props.showTokenName);
    const [toaddress, setToAddress] = React.useState(null);
    const [userTokenBalanceInput, setTokenBalanceInput] = React.useState(0);
    const [convertedAmountValue, setConvertedAmountValue] = React.useState(null);
    const mint = props.mint;
    const logoURI = props.logoURI;
    const name = props.name;
    const balance = props.balance;
    const conversionrate = props.conversionrate;
    const sendtype = props.sendType || 0; // 0 regular 1 to grape treasury
    const [memotype, setMemoType] = React.useState(0);
    const [memoref, setMemoRef] = React.useState('');
    const [memonotes, setMemoNotes] = React.useState(''); 
    const [memoText, setMemoText] = React.useState(null); 
    const freeconnection = RPC_CONNECTION;
    const { connection } = useConnection();
    const { publicKey, wallet, sendTransaction } = useWallet();
    const { enqueueSnackbar, closeSnackbar } = useSnackbar();
    const onError = useCallback(
        (error: WalletError) => {
            enqueueSnackbar(error.message ? `${error.name}: ${error.message}` : error.name, { variant: 'error' });
            console.error(error);
        },
        [enqueueSnackbar]
    );
    const handleClickOpen = () => {

        if (sendtype === 1) 
            setToAddress(GRAPE_TREASURY);

        setTokenBalanceInput(0);
        setConvertedAmountValue(0);
        setOpen(true);
    };
    const handleClose = () => {
        setOpen(false);
    };

    const handleSelectChange = (event: SelectChangeEvent) => {
        setMemoType(+(event.target.value as string));
      };

    async function transferTokens(tokenMintAddress: string, to: string, amount: number) {
        const fromWallet = publicKey;
        const toWallet = new PublicKey(toaddress);
        const mintPubkey = new PublicKey(tokenMintAddress);
        const amountToSend = +amounttosend;
        const tokenAccount = new PublicKey(mintPubkey);
        
        let GRAPE_TT_MEMO = {
            status:1, // status
            type:memotype, // AMA - SETUP 
            ref:memoref, // SOURCE
            notes:memonotes
        };
        
        if (memoText){
            GRAPE_TT_MEMO = memoText
        }
        

        if (tokenMintAddress == "So11111111111111111111111111111111111111112"){ // Check if SOL
            const decimals = 9;
            const adjustedAmountToSend = amountToSend * Math.pow(10, decimals);
            const transaction = new Transaction()
            .add(
                SystemProgram.transfer({
                    fromPubkey: fromWallet,
                    toPubkey: toWallet,
                    lamports: adjustedAmountToSend,
                })
            ).add(
                new TransactionInstruction({
                    keys: [{ pubkey: fromWallet, isSigner: true, isWritable: true }],
                    data: Buffer.from(JSON.stringify(GRAPE_TT_MEMO), 'utf-8'),
                    programId: new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"),
                })
            );
            try{
                enqueueSnackbar(`Preparing to send ${amountToSend} ${name} to ${toaddress}`,{ variant: 'info' });
                const signature = await sendTransaction(transaction, freeconnection);
                const snackprogress = (key:any) => (
                    <CircularProgress sx={{padding:'10px'}} />
                );
                const cnfrmkey = enqueueSnackbar(`Confirming transaction`,{ variant: 'info', action:snackprogress, persist: true });
                //await connection.confirmTransaction(signature, 'processed');
                const latestBlockHash = await connection.getLatestBlockhash();
                await connection.confirmTransaction({
                    blockhash: latestBlockHash.blockhash,
                    lastValidBlockHeight: latestBlockHash.lastValidBlockHeight,
                    signature: signature}, 
                    'processed'
                );
                closeSnackbar(cnfrmkey);
                const action = (key:any) => (
                        <Button href={`https://explorer.solana.com/tx/${signature}`} target='_blank'  sx={{color:'white'}}>
                            Signature: {signature}
                        </Button>
                );
                enqueueSnackbar(`Sent ${amountToSend} ${name} to ${toaddress}`,{ variant: 'success', action });
            }catch(e){
                enqueueSnackbar(e.message ? `${e.name}: ${e.message}` : e.name, { variant: 'error' });
            } 
        } else{
            const accountInfo = await connection.getParsedAccountInfo(tokenAccount);
            const accountParsed = JSON.parse(JSON.stringify(accountInfo.value.data));
            const decimals = accountParsed.parsed.info.decimals;
            
            //tokenMintAddress
            /*
            console.log("TOKEN_PROGRAM_ID: "+TOKEN_PROGRAM_ID.toBase58())
            console.log("ASSOCIATED_TOKEN_PROGRAM_ID: "+ASSOCIATED_TOKEN_PROGRAM_ID.toBase58())
            console.log("mintPubkey: "+mintPubkey.toBase58())
            console.log("fromWallet: "+fromWallet.toBase58())
            console.log("toWallet: "+toWallet.toBase58())
            */

            let fromTokenAccount = await getOrCreateAssociatedTokenAccount(
                connection,
                fromWallet,
                mintPubkey,
                fromWallet,
                !ValidateAddress(fromWallet.toBase58()),
                TOKEN_PROGRAM_ID,
                ASSOCIATED_TOKEN_PROGRAM_ID
            );
            
            //console.log("validateAddress onCurve: "+ValidateAddress(toWallet.toBase58()))

            try{
                let toTokenAccount = await getOrCreateAssociatedTokenAccount(
                    connection,
                    fromWallet,
                    mintPubkey,
                    toWallet,
                    !ValidateAddress(toWallet.toBase58()),
                    TOKEN_PROGRAM_ID,
                    ASSOCIATED_TOKEN_PROGRAM_ID
                );

                const adjustedAmountToSend = amountToSend * Math.pow(10, decimals);
                
                const transaction = new Transaction();
                if (toTokenAccount){
                    transaction
                    .add(
                        createTransferInstruction(
                            fromTokenAccount.address,
                            toTokenAccount.address,
                            publicKey,
                            adjustedAmountToSend,
                            [],
                            TOKEN_PROGRAM_ID,
                        )
                    )
                    .add(
                        new TransactionInstruction({
                            keys: [{ pubkey: fromWallet, isSigner: true, isWritable: true }],
                            data: Buffer.from(JSON.stringify(GRAPE_TT_MEMO), 'utf-8'),
                            programId: new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"),
                        })
                    );
                } else{
                    console.log("Skipping: "+toWallet.toBase58()+ " could not get ATA (TokenAccountNotFoundError)");
                } 
                
                try{
                    enqueueSnackbar(`Preparing to send ${amountToSend} ${name} to ${toaddress}`,{ variant: 'info' });
                    const signature = await sendTransaction(transaction, freeconnection);
                    const snackprogress = (key:any) => (
                        <CircularProgress sx={{padding:'10px'}} />
                    );
                    const cnfrmkey = enqueueSnackbar(`Confirming transaction`,{ variant: 'info', action:snackprogress, persist: true });
                    //await connection.confirmTransaction(signature, 'processed');
                    const latestBlockHash = await connection.getLatestBlockhash();
                    await connection.confirmTransaction({
                        blockhash: latestBlockHash.blockhash,
                        lastValidBlockHeight: latestBlockHash.lastValidBlockHeight,
                        signature: signature}, 
                        'processed'
                    );
                    closeSnackbar(cnfrmkey);
                    const action = (key:any) => (
                        <Button href={`https://explorer.solana.com/tx/${signature}`} target='_blank' sx={{color:'white'}} >
                            Signature: {signature}
                        </Button>
                    );
                    enqueueSnackbar(`Sent ${amountToSend} ${name} to ${toaddress}`,{ variant: 'success', action });
                }catch(e){
                    closeSnackbar();
                    enqueueSnackbar(e.message ? `${e.name}: ${e.message}` : e.name, { variant: 'error' });
                } 
            } catch(err){
                closeSnackbar();
                enqueueSnackbar(err.message ? `${err.name}: ${err.message}` : err.name, { variant: 'error' });
            }
            
        }
    }
    
    function HandleSendSubmit(event: any) {
        event.preventDefault();
        if (amounttosend >= 0){
            if (toaddress){
                if ((toaddress.length >= 32) && 
                    (toaddress.length <= 44)){ // very basic check / remove and add twitter handle support (handles are not bs58)
                    transferTokens(mint, toaddress, amounttosend);
                    handleClose();
                } else{
                    // Invalid Wallet ID
                    enqueueSnackbar(`Enter a valid Wallet Address!`,{ variant: 'error' });
                    console.log("INVALID WALLET ID");
                }
            } else{
                enqueueSnackbar(`Enter a valid Wallet Address!`,{ variant: 'error' });
            }
        }else{
            enqueueSnackbar(`Enter the balance you would like to send`,{ variant: 'error' });
        }
    }

    React.useEffect(() => {
         setConvertedAmountValue(amounttosend*conversionrate);
    }, [amounttosend]);
    
    return (
        <div>

            

            {showTokenName ? 
                <Button
                    variant="outlined" 
                    //aria-controls={menuId}
                    title={`Send ${name}`}
                    onClick={handleClickOpen}
                    size="small"
                    //onClick={isConnected ? handleProfileMenuOpen : handleOpen}
                    >
                    <ArrowCircleRightIcon sx={{mr:1}} /> {name}   
                </Button>
            :
                <IconButton 
                    color="primary"
                    title={`Send ${name}`}
                    size="small"
                    aria-label="Send" 
                    onClick={handleClickOpen}>
                    <ArrowCircleRightOutlinedIcon fontSize="small" />
                </IconButton>
            }   
        <BootstrapDialog
            onClose={handleClose}
            aria-labelledby="customized-dialog-title"
            open={open}
            PaperProps={{ 
                style: {
                    background: 'linear-gradient(to right, #251a3a, #000000)',
                    boxShadow: '3',
                    border: '1px solid rgba(255,255,255,0.15)',
                    borderTop: '1px solid rgba(255,255,255,0.3)',
                    borderRadius: '20px',
                    padding:'4'
                    },
                }}
        >
            <form onSubmit={HandleSendSubmit}>
                <BootstrapDialogTitle id="customized-dialog-title" onClose={handleClose}>
                    Send {name}
                </BootstrapDialogTitle>
                <DialogContent dividers>
                    <FormControl>
                        <Grid container spacing={2}>
                            <Grid item xs={4}>
                                
                            <Grid container direction="row" alignItems="center">
                                <Grid item>
                                    {logoURI ? 
                                        <Avatar component={Paper} 
                                            elevation={4}
                                            alt="Token" 
                                            src={logoURI}
                                            sx={{ width: 28, height: 28, bgcolor: "#222" }}
                                        /> : <HelpIcon />}
                                </Grid>
                                <Grid item sx={{ ml: 1 }}>
                                    {name || (mint && trimAddress(mint)) || ''}
                                </Grid>
                            </Grid>
                            </Grid>
                            <Grid item xs={8}>
                                <RegexTextField
                                    regex={/[^0-9]+\.?[^0-9]/gi}
                                    autoFocus
                                    autoComplete='off'
                                    margin="dense"
                                    id="send-token-amount" 
                                    type="text"
                                    fullWidth
                                    variant="standard"
                                    value={userTokenBalanceInput || 0}
                                    onChange={(e: any) => {
                                        let val = e.target.value.replace(/^0+/, '');
                                        setTokensToSend(val)
                                        setTokenBalanceInput(val)
                                        }
                                    }
                                    inputProps={{
                                        style: { 
                                            textAlign:'right', 
                                            fontSize: '24px'
                                        }
                                    }}
                                />
                            </Grid>
                            <Grid item xs={6}>
                                <Typography
                                    variant="caption"
                                >
                                    Balance: {balance} 
                                    <ButtonGroup variant="text" size="small" aria-label="outlined primary button group" sx={{ml:1}}>
                                        <Button 
                                            onClick={() => {
                                                setTokensToSend(balance)
                                                setTokenBalanceInput(+balance) }}
                                        > 
                                            Max 
                                        </Button>
                                        <Button  
                                            onClick={() => {
                                                setTokensToSend(+balance/2)
                                                setTokenBalanceInput(+balance/2) }}
                                        > 
                                            Half
                                        </Button>
                                    </ButtonGroup>
                                </Typography>
                            </Grid>
                            <Grid item xs={6}
                                sx={{
                                    textAlign:'right'
                                }}
                            >
                                <Typography
                                    variant="caption"
                                >
                                    {convertedAmountValue ?
                                        <>
                                        {+convertedAmountValue > 0 &&
                                            <>
                                            ~ ${convertedAmountValue.toFixed(2)}
                                            </>
                                        }
                                        </>
                                    :<></>}
                                </Typography>
                            </Grid>
                            
                            {sendtype === 0 ? 
                            (
                                <>
                                    <Grid item xs={12}>
                                        <TextField 
                                            id="send-to-address" 
                                            fullWidth 
                                            placeholder="Enter a Solana address" 
                                            label="To address" 
                                            variant="standard"
                                            autoComplete="off"
                                            onChange={(e) => {setToAddress(e.target.value)}}
                                            InputProps={{
                                                inputProps: {
                                                    style: {
                                                        textAlign:'center'
                                                    }
                                                }
                                            }}
                                        />
                                    </Grid>

                                    <Grid item xs={12}>
                                        <TextField 
                                            id="send-to-memo" 
                                            fullWidth 
                                            placeholder="Add a memo for your transaction" 
                                            label="Memo" 
                                            variant="standard"
                                            autoComplete="off"
                                            onChange={(e) => {setMemoText(e.target.value)}}
                                            InputProps={{
                                                inputProps: {
                                                    style: {
                                                        textAlign:'left'
                                                    }
                                                }
                                            }}
                                        />
                                    </Grid>
                                </>
                            ) : (
                                <>
                                    <Grid item xs={12}>
                                        <TextField 
                                            id="send-to-address" 
                                            fullWidth 
                                            placeholder="Enter any Solana address" 
                                            label="To address" 
                                            variant="standard"
                                            autoComplete="off"
                                            value={GRAPE_TREASURY}
                                            disabled={true}
                                            onChange={(e) => {setToAddress(e.target.value)}}
                                            InputProps={{
                                                inputProps: {
                                                    style: {
                                                        textAlign:'center'
                                                    }
                                                }
                                            }}
                                        />
                                    </Grid>
                                    
                                    <Grid item xs={12}>
                                        <FormControl fullWidth>
                                            <InputLabel id="demo-simple-select-label">Type</InputLabel>
                                            <Select
                                                labelId="demo-simple-select-label"
                                                id="demo-simple-select"
                                                value={(memotype.toString())}
                                                label="Type"
                                                onChange={handleSelectChange}
                                            >
                                                <MenuItem value={8}>Tools</MenuItem>
                                                <MenuItem value={1}>AMA</MenuItem>
                                                <MenuItem value={2}>Content</MenuItem>
                                                <MenuItem value={3}>Development</MenuItem>
                                                <MenuItem value={4}>Events</MenuItem>
                                                <MenuItem value={5}>Moderation</MenuItem>
                                                <MenuItem value={6}>Organization</MenuItem>
                                                <MenuItem value={7}>Parternship</MenuItem>
                                            </Select>
                                        </FormControl>
                                    </Grid>

                                    <Grid item xs={12}>
                                        <TextField 
                                            id="send-to-ref" 
                                            fullWidth 
                                            placeholder="Sender" 
                                            label="Sender/Community Name" 
                                            variant="standard"
                                            autoComplete="off"
                                            onChange={(e) => {setMemoRef(e.target.value)}}
                                            InputProps={{
                                                inputProps: {
                                                    style: {
                                                        textAlign:'left'
                                                    }
                                                }
                                            }}
                                        />
                                    </Grid>

                                    <Grid item xs={12}>
                                        <TextField 
                                            id="send-to-notes" 
                                            fullWidth 
                                            placeholder="Notes" 
                                            label="Contribution Reason" 
                                            variant="standard"
                                            autoComplete="off"
                                            onChange={(e) => {setMemoNotes(e.target.value)}}
                                            InputProps={{
                                                inputProps: {
                                                    style: {
                                                        textAlign:'left'
                                                    }
                                                }
                                            }}
                                        />
                                    </Grid>
                                </>
                            )}

                        </Grid>
                    </FormControl>
                </DialogContent>
                <DialogActions>
                    <Button     
                        fullWidth
                        type="submit"
                        variant="outlined" 
                        title="Send"
                        disabled={
                            (userTokenBalanceInput > +balance) || (userTokenBalanceInput <= 0)
                        }
                        sx={{
                            margin:1
                        }}>
                        Send
                    </Button>
                </DialogActions>
            </form>
        </BootstrapDialog>
        </div>
    );
}