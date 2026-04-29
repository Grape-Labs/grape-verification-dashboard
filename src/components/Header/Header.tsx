import * as React from 'react';
import { Link, useLocation, NavLink } from 'react-router-dom';
import {CopyToClipboard} from 'react-copy-to-clipboard';
import Box from '@mui/material/Box';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';

import { useSnackbar } from 'notistack';

import MuiAlert, { AlertProps } from '@mui/material/Alert';
import Snackbar, { SnackbarOrigin } from '@mui/material/Snackbar';


//import Wallet from '../../utils/wallet/Wallet';
//import PhantomWallet from '../../utils/wallet/Phantom';
//import SolflareWallet from '../../utils/wallet/Solflare';

import { useSession } from "../../contexts/session";

import {
    MenuItem,
    Menu,
    Tooltip,
    Dialog,
    DialogTitle,
    List,
    ListItem,
    ListItemText,
    Hidden
} from '@mui/material';

import { 
    DASHBOARD_LOGO
} from '../Tools/constants';

import { AccountBalanceWalletOutlined } from '@mui/icons-material';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import BrowseGalleryIcon from '@mui/icons-material/BrowseGallery';
import DownloadingIcon from '@mui/icons-material/Downloading';
import StorageIcon from '@mui/icons-material/Storage';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import AssessmentIcon from '@mui/icons-material/Assessment';
import GroupWorkIcon from '@mui/icons-material/GroupWork';
import LinkOffIcon from '@mui/icons-material/LinkOff';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import DashboardIcon from '@mui/icons-material/Dashboard';
import ImageIcon from '@mui/icons-material/Image';
import RssFeedIcon from '@mui/icons-material/RssFeed';
import IconButton from '@mui/material/IconButton';
import LocalOfferIcon from '@mui/icons-material/LocalOffer';

import DashboardOutlinedIcon from '@mui/icons-material/DashboardOutlined';
import PhotoOutlinedIcon from '@mui/icons-material/PhotoOutlined';
import InsertChartOutlinedIcon from '@mui/icons-material/InsertChartOutlined';

import ConnectDialog from '../ConnectDialog/ConnectDialog';

export interface State extends SnackbarOrigin {
    open: boolean;
}

function getParam(param: string) {
    //return new URLSearchParams(document.location.search).get(param);
    return new URLSearchParams(window.location.search).get(param);
}

interface HeaderProps{
    children?:React.ReactNode;
}

const Alert = React.forwardRef<HTMLDivElement, AlertProps>(function Alert(
    props,
    ref,
    ) {
    return <MuiAlert elevation={6} ref={ref} variant="filled" {...props} />;
});

export function Header(props: any) {
    const { open_menu } = props;
    const [open_snackbar, setSnackbarState] = React.useState(false);
    
    const { session, setSession } = useSession();
    const [tokenParam, setTokenParam] = React.useState(getParam('token'));
    const [discordId, setDiscordId] = React.useState(getParam('discord_id'));
    const [userId, setUserId] = React.useState(getParam('user_id'));
    const [providers, setProviders] = React.useState(['Sollet', 'Sollet Extension', 'Phantom','Solflare']);
    const [open_wallet, setOpenWallet] = React.useState(false);
    
    const [anchorEl, setAnchorEl] = React.useState(null);
    const isWalletOpen = Boolean(anchorEl);
    const wallets = session && session.userWallets;

    const location = useLocation();
    const currPath = location.pathname;
    const searchParams = new URLSearchParams(location.search);
    //const currPath = location?.pathname ?? "";
    const { enqueueSnackbar } = useSnackbar();

    const isConnected = session && session.isConnected;

    async function disconnect() {
        setSession(null);
        window.location.href = "/"
    }    

    //Menu
    const menuId = 'primary-wallet-account-menu';
    const menuWalletId = 'primary-fullwallet-account-menu';

    const handleProfileMenuOpen = (event: any) => {
        setAnchorEl(event.currentTarget);
    };

    const handleMenuClose = () => {
        setAnchorEl(null);
        // this.props.parentCallback("Data from child");
    };

    const handleWalletConnectClickOpen = (type: string, callback: any) => {
        callback && callback();
    };

    const handleCloseWallet = (value: any) => {
        setOpenWallet(false);

    };

    function SimpleDialog(props: any) {
        const { onClose, selectedValue } = props;

        const handleCloseWallet = () => {
            onClose(selectedValue);
        };

        const handleListItemClick = (value: any) => {
            onClose(value);
        };

        return (
            <Dialog onClose={handleCloseWallet} aria-labelledby="simple-dialog-title" open={open_wallet}>
                <DialogTitle id="simple-dialog-title">Select Wallet</DialogTitle>
                <List>
                    {providers.map((provider) => (
                        <ListItem button onClick={() => handleListItemClick(provider)} key={provider}>
                            <ListItemText primary={provider} />
                        </ListItem>
                    ))}
                </List>
            </Dialog>
        );
    }

    const handleClickSnackbar = () => {
        enqueueSnackbar(`Copied...`,{ variant: 'success' });
        
        handleMenuClose();
        //setSnackbarState(true);
    };

    const handleCloseSnackbar = (event?: React.SyntheticEvent, reason?: string) => {
        if (reason === 'clickaway') {
            return;
        }
        setSnackbarState(false);
    };

    const navIconSx = {
        width: 40,
        height: 40,
        borderRadius: '14px',
        color: 'text.primary',
        border: '1px solid rgba(255,255,255,0.08)',
        background: 'rgba(255,255,255,0.04)',
        backdropFilter: 'blur(16px)',
        p: 0,
        '&:hover': {
            background: 'rgba(241, 201, 107, 0.14)',
            borderColor: 'rgba(241, 201, 107, 0.35)',
        },
    };


    return (

        <Toolbar
            className="grape-dashboard-header"
            color="inherit"
            sx={{
                minHeight: 64,
                pr: '24px', // keep right padding when drawer closed
                pl: { xs: 1, sm: 2 },
                background: 'none'
            }}
            >
            
            <Box display='flex' flexGrow={1} alignItems="center" gap={1.25}>
                <Tooltip title={`Dashboard`}>
                    <IconButton sx={{ borderRadius:'16px', px: 1, py: 0.5 }} component={NavLink} color="inherit" to="/">
                        <Box display="flex" alignItems="center" gap={1}>
                            <img src={DASHBOARD_LOGO} height="40px" className="header-logo" alt="Grape" />
                            <Box sx={{ display: { xs: 'none', sm: 'flex' }, flexDirection: 'column', alignItems: 'flex-start' }}>
                                <Typography component="h1" variant="subtitle1" color="inherit" noWrap sx={{ fontWeight: 800, lineHeight: 1.1 }}>
                                    Grape Access
                                </Typography>
                                <Typography variant="caption" sx={{ color: 'text.secondary', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                                    Verification
                                </Typography>
                            </Box>
                        </Box>
                    </IconButton>
                </Tooltip>
                

                {/*
                <Tooltip title={`GAN`}><IconButton sx={{borderRadius:'17px'}} component={NavLink} to='/admin'><AdminPanelSettingsIcon/></IconButton></Tooltip>
                */}
                <Tooltip title={`Collection`}><IconButton sx={navIconSx} component="a" href='https://grapedao.org' target="_blank"><PhotoOutlinedIcon/></IconButton></Tooltip>
                <Tooltip title={`Wallet`}><IconButton sx={navIconSx} component="a" href='https://grapedao.org/identity' target="_blank"><AccountBalanceWalletOutlined/></IconButton></Tooltip>
                
                {/*
                <Tooltip title={`Staking`}><IconButton sx={{borderRadius:'17px'}} component="a" href='https://grapestaking.vercel.app' target="_blank"><BrowseGalleryIcon/></IconButton></Tooltip>
                */} 
                <Hidden smDown>
                    {/*
                    <Tooltip title={`Grape Drive`}><IconButton sx={{borderRadius:'17px'}} component="a" href='https://grapedrive.vercel.app' target="_blank"><StorageIcon/></IconButton></Tooltip>
                    <Tooltip title={`Streams`}><IconButton sx={{borderRadius:'17px'}} component={NavLink} color="inherit" to="/streams"><DownloadingIcon /></IconButton></Tooltip>
                    */}
                    <Tooltip title={`About`}><IconButton sx={navIconSx} component="a" href='https://grapedao.org' target="_blank"><InfoOutlinedIcon/></IconButton></Tooltip>
                </Hidden>
            </Box>
            <div>

                {currPath !== "/register" && currPath !== "/start" ?
                    <>
                    {searchParams.toString().length <= 100 &&
                        
                        <div className="header-action">
                            <ConnectDialog 
                                session={session}
                                isConnected={isConnected}
                                userId={userId}
                                menuId='primary-wallet-account-menu'
                                menuWalletId='primary-fullwallet-account-menu'
                                handleProfileMenuOpen={handleProfileMenuOpen}
                                handleClickOpen={handleWalletConnectClickOpen}
                                buttonText="Connect"
                                nakedWallet={false}
                                login={true}   
                                token={null}   
                                discordId={null} 
                            />

                            
                            <Box sx={{ display: { xs: 'flex', md: 'none' } }}>
                                <Menu
                                    anchorEl={anchorEl}
                                    id={menuId}
                                    keepMounted
                                    open={isWalletOpen}
                                    //open={open_wallet}
                                    onClose={handleMenuClose}
                                >
                                    <CopyToClipboard 
                                        text={session.publicKey} 
                                        //onCopy={copySnackbar}>
                                        onCopy={handleClickSnackbar}>
                                        <MenuItem>
                                            <ContentCopyIcon sx={{ mr:1 }} /> Copy to clipboard
                                        </MenuItem>
                                    </CopyToClipboard>
                                    <MenuItem
                                        component="a"
                                        href={`https://explorer.solana.com/address/${session.publicKey}`}
                                        target="_blank"
                                    >
                                        <OpenInNewIcon sx={{ mr:1 }} /> Explore
                                    </MenuItem>
                                    <MenuItem onClick={disconnect}><LinkOffIcon sx={{ mr:1 }} />Disconnect</MenuItem>
                                </Menu>
                            </Box>

                            <SimpleDialog open={open_wallet} onClose={handleCloseWallet} />
                            
                        </div>
                    }
                </>
                :
                <>
                </>
                }
            </div>
        </Toolbar>
        
    );
}

export default Header;
