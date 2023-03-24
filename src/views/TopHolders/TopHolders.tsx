import React, { FC, useCallback } from 'react';

import { styled } from '@mui/material/styles';

import { Connection, PublicKey } from '@solana/web3.js';

import {
  Dialog,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Grid,
  Skeleton,
  Typography,
  DialogTitle,
  DialogContent,
  Chip,
  Avatar,
} from '@mui/material';

import { PretifyCommaNumber } from '../../components/Tools/PretifyCommaNumber';
import { MakeLinkableAddress, ValidateAddress } from '../../components/Tools/WalletAddress'; // global key handling

import IconButton from '@mui/material/IconButton';
import CloseIcon from '@mui/icons-material/Close';
import AccountBalanceIcon from '@mui/icons-material/AccountBalance';
import { RPC_CONNECTION } from '../../components/Tools/constants';

const StyledTable = styled(Table)(({ theme }) => ({
  '& .MuiTableCell-root': {
    borderBottom: '1px solid rgba(255,255,255,0.05)',
  },
  '& .MuiTableContainer-root': {
    backgroundColor: 'none',  
  },
}));

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

export default function TopHolders(props: any) {
    const [open, setOpen] = React.useState(false);
    const [largestAccounts, setLargestAccounts] = React.useState(null);
    const [tokenSupply, setTokenSupply] = React.useState(null);
    const mint = props.mint;
    const logoURI = props.logoURI;
    const name = props.name;
    const ggoconnection = RPC_CONNECTION;

    const handleClickOpen = () => {
        setOpen(true);
    };
    const handleClose = () => {
        setOpen(false);
    };

    const GetLargestTokenAccounts = async () => {
      const response = await ggoconnection.getTokenLargestAccounts(new PublicKey(mint));
      const resultValues = response.value;
      return resultValues;
    };

    const GetTokenSupply = async () => {
      const response = await ggoconnection.getTokenSupply(new PublicKey(mint));
      const resultValues = response.value;
      return resultValues;
    };
    
    const fetchTokenAccountData = async () => {
      let flargestTokenAccounts = await Promise.all([GetLargestTokenAccounts()]);
      setLargestAccounts(flargestTokenAccounts);
    }
    const fetchTokenSupply = async () => {
      //try{
        let ftokenSupply = await Promise.all([GetTokenSupply()]);
        setTokenSupply(ftokenSupply);
      //}catch(e){console.log("ERR: "+e);}
    }

    React.useEffect(() => { 
      if (!largestAccounts){
        fetchTokenAccountData();
      }
      if (!tokenSupply){
        fetchTokenSupply();
      }
    }, [mint]);
    
    return (
      <React.Fragment>
            <Button
                variant="outlined" 
                //aria-controls={menuId}
                title={`Top 20 ${name} Holders`}
                onClick={handleClickOpen}
                size="small"
                >
                <AccountBalanceIcon sx={{mr:1}} /> {name} Holders
            </Button>
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
              <BootstrapDialogTitle id="customized-dialog-title" onClose={handleClose}>
                Top 20 {name} Holders
              </BootstrapDialogTitle>
              <DialogContent dividers>

              {tokenSupply && 
                <>
                {+tokenSupply.amount > 0 &&
                  <Grid container spacing={3}                  
                    direction="column"
                    alignItems="center"
                    justifyContent="center"
                    >
                    <Grid item>
                        <Typography
                          variant="h6"
                          textAlign="center"
                        >
                        <PretifyCommaNumber number={parseFloat(tokenSupply.uiAmountString).toFixed(2)} />
                        <br/>
                        <Chip 
                          avatar={<Avatar alt={name} src={logoURI} />}
                          color="primary"
                          size="small"
                          label="Current Total Supply" 
                          variant="outlined" />
                        </Typography>
                    </Grid>
                  </Grid>
                }
                </> 
              }

                <TableContainer>
                  <StyledTable sx={{ minWidth: 500 }} size="small" aria-label="Portfolio Table">
                    <TableHead>
                      <TableRow>
                        <TableCell></TableCell>
                        <TableCell align="center">Address</TableCell>
                        <TableCell align="right">Holdings</TableCell>
                        {tokenSupply && 
                          <>
                            {+tokenSupply.amount > 0 &&
                              <TableCell align="right"></TableCell>
                            }
                          </>
                        }
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {largestAccounts ? largestAccounts.map((item: any, index: number) => (
                        <TableRow
                          key={item.address}
                          sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
                        >
                          <TableCell component="th" scope="row">{index+1}</TableCell>
                          <TableCell component="th" scope="row">  
                            <MakeLinkableAddress addr={item.address} trim={4} hasextlink={true} hascopy={true} fontsize={12} />
                          </TableCell>
                          <TableCell align="right">
                            <PretifyCommaNumber number={parseFloat(item.uiAmountString).toFixed(2)} />
                          </TableCell>
                          <TableCell align="right">
                            {tokenSupply && 
                              <>
                                {+tokenSupply.amount > 0 &&
                                <>
                                {(parseFloat(item.uiAmountString)/parseFloat(tokenSupply.uiAmountString)*100).toFixed(2)}
                                %
                                </>
                                }
                              </>
                            }
                          </TableCell>
                        </TableRow>
                        ))
                        :
                        <React.Fragment>
                            <TableRow>
                                <TableCell><Skeleton/></TableCell>
                                <TableCell><Skeleton/></TableCell>
                                <TableCell><Skeleton/></TableCell>
                                <TableCell><Skeleton/></TableCell>
                            </TableRow>
                            <TableRow>
                                <TableCell><Skeleton/></TableCell>
                                <TableCell><Skeleton/></TableCell>
                                <TableCell><Skeleton/></TableCell>
                                <TableCell><Skeleton/></TableCell>
                            </TableRow>
                            <TableRow>
                                <TableCell><Skeleton/></TableCell>
                                <TableCell><Skeleton/></TableCell>
                                <TableCell><Skeleton/></TableCell>
                                <TableCell><Skeleton/></TableCell>
                            </TableRow>
                        </React.Fragment>
                      }
                    </TableBody>
                  </StyledTable>
                </TableContainer>
              </DialogContent>
            </BootstrapDialog>
      </React.Fragment>
    );
}