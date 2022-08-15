import * as React from 'react';
import { useState, useEffect } from "react";
import { useSession } from "../../contexts/session";
import UserServer from '../../models/UserServer';
import TwitterFeed from '../Feed/TwitterFeed';
import PropTypes from 'prop-types';
import { visuallyHidden } from '@mui/utils';
import { DataGrid, GridColDef, GridValueGetterParams } from '@mui/x-data-grid';
import MUIDataTable from "mui-datatables";

import {
  Grid,
  Typography,
  Collapse,
  Button,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableContainer,
  TableSortLabel,
  TableRow,
  TableFooter,
  TablePagination,
  TextField,
  Tooltip,
  Paper,
  Box,
  InputLabel,
  InputBase,
  Avatar,
} from '@mui/material';

import { makeStyles, styled, alpha, useTheme } from '@mui/material/styles';

import DiscordIcon from '../../components/StaticIcons/DiscordIcon';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import CircleOutlinedIcon from '@mui/icons-material/CircleOutlined';

import QrCode2Icon from '@mui/icons-material/QrCode2';
import KeyboardArrowDownIcon from '@mui/icons-material/KeyboardArrowDown';
import KeyboardArrowUpIcon from '@mui/icons-material/KeyboardArrowUp';
import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutline';
import RemoveCircleOutlineIcon from '@mui/icons-material/RemoveCircleOutline';
import IconButton from '@mui/material/IconButton';
import FirstPageIcon from '@mui/icons-material/FirstPage';
import KeyboardArrowLeft from '@mui/icons-material/KeyboardArrowLeft';
import KeyboardArrowRight from '@mui/icons-material/KeyboardArrowRight';
import LastPageIcon from '@mui/icons-material/LastPage';
import { id } from 'ethers/lib/utils';

const CssTextField = styled(TextField)({
  '& label.Mui-focused': {
    color:'white',
    //color: 'green',
  },
  '& .MuiInput-underline:after': {
    borderBottomColor: 'white',
    //borderBottomColor: 'green',
  },
  '& .MuiOutlinedInput-root': {
    '& fieldset': {
      borderColor: 'rgba(255,255,255,0.25)',
      borderRadius: 12,
    },
    '&:hover fieldset': {
      borderColor: 'rgba(255,255,255,0.75)',
      //borderColor: 'yellow',
    },
    '&.Mui-focused fieldset': {
      borderColor: 'rgb(255,255,255)',
      //borderColor: 'green',
    },
  },
  '& .MuiInputBase-input': {
  }
});

const BootstrapInput = styled(InputBase)(({ theme }) => ({
  'label + &': {
    marginTop: theme.spacing(3),
  },
  '& .MuiInputBase-input': {
    borderRadius: 4,
    position: 'relative',
    backgroundColor: theme.palette.mode === 'light' ? '#fcfcfb' : '#2b2b2b',
    border: '1px solid #ced4da',
    fontSize: 16,
    width: 'auto',
    padding: '10px 12px',
    transition: theme.transitions.create([
      'border-color',
      'background-color',
      'box-shadow',
    ]),
    // Use the system font instead of the default Roboto font.
    fontFamily: [
      '-apple-system',
      'BlinkMacSystemFont',
      '"Segoe UI"',
      'Roboto',
      '"Helvetica Neue"',
      'Arial',
      'sans-serif',
      '"Apple Color Emoji"',
      '"Segoe UI Emoji"',
      '"Segoe UI Symbol"',
    ].join(','),
    '&:focus': {
      boxShadow: `${alpha(theme.palette.primary.main, 0.25)} 0 0 0 0.2rem`,
      borderColor: theme.palette.primary.main,
    },
  },
}));

const ValidationTextField = styled(TextField)({
  '& input:valid + fieldset': {
    borderColor: 'green',
    borderWidth: 2,
  },
  '& input:invalid + fieldset': {
    borderColor: 'red',
    borderWidth: 2,
  },
  '& input:valid:focus + fieldset': {
    borderLeftWidth: 6,
    padding: '4px !important', // override inline-style
  },
});

const StyledTable = styled(Table)(({ theme }) => ({
  '& .MuiTable-root': {
    background: 'none', 
  },
  '& .MuiPaper-root': {
    background: 'none', 
  },
  '& .MuiToolbar-root': {
    height:'44px',
    minHeight:'44px!important'
  },
  '& .MuiTableRow-root': {
    height: '10px', 
  },
  '& .MuiAvatar-circular.MuiPaper-root': {
    background: '#333', 
  },
  '& .MuiTableCell-root.MuiTableCell-body': {
    lineHeight:'1.25em',
    padding:4
  },
  '& .MuiTableCell-root.MuiTableCell-head': {
    lineHeight:'1.25em',
    padding:4
  },
  '& .MuiTableCell-root': {
    background: 'none', 
    borderBottom: '1px solid rgba(255,255,255,0.05)',
  },
}));

function TablePaginationActions(props) {
  const theme = useTheme();
  const { count, page, rowsPerPage, onPageChange } = props;

  const handleFirstPageButtonClick = (event) => {
    onPageChange(event, 0);
  };

  const handleBackButtonClick = (event) => {
    onPageChange(event, page - 1);
  };

  const handleNextButtonClick = (event) => {
    onPageChange(event, page + 1);
  };

  const handleLastPageButtonClick = (event) => {
    onPageChange(event, Math.max(0, Math.ceil(count / rowsPerPage) - 1));
  };
  
  return (
      <Box sx={{ flexShrink: 0, ml: 2.5 }}>
          <IconButton
              onClick={handleFirstPageButtonClick}
              disabled={page === 0}
              aria-label="first page"
          >
              {theme.direction === "rtl" ? <LastPageIcon /> : <FirstPageIcon />}
          </IconButton>
          <IconButton
              onClick={handleBackButtonClick}
              disabled={page === 0}
              aria-label="previous page"
          >
              {theme.direction === "rtl" ? (
                  <KeyboardArrowRight />
              ) : (
                  <KeyboardArrowLeft />
              )}
          </IconButton>
          <IconButton
              onClick={handleNextButtonClick}
              disabled={page >= Math.ceil(count / rowsPerPage) - 1}
              aria-label="next page"
          >
              {theme.direction === "rtl" ? (
                  <KeyboardArrowLeft />
              ) : (
                  <KeyboardArrowRight />
              )}
          </IconButton>
          <IconButton
              onClick={handleLastPageButtonClick}
              disabled={page >= Math.ceil(count / rowsPerPage) - 1}
              aria-label="last page"
          >
              {theme.direction === "rtl" ? <FirstPageIcon /> : <LastPageIcon />}
          </IconButton>
      </Box>
  );
}

TablePaginationActions.propTypes = {
  count: PropTypes.number.isRequired,
  onPageChange: PropTypes.func.isRequired,
  page: PropTypes.number.isRequired,
  rowsPerPage: PropTypes.number.isRequired,
};

export const ServersView = (props) => {
  const [orderT1, setOrderT1] = React.useState('asc');
  const [orderByT1, setOrderByT1] = React.useState('server.name');
  const [order, setOrder] = React.useState('asc');
  const [orderBy, setOrderBy] = React.useState('server.name');
  const [tab, setTab] = useState(0);
  const { session, setSession } = useSession();
  const [filterVal, setFilterVal] = React.useState("");

  const [fullServerRows, setFullServerRows] = useState(null);
  const [servers, setServers] = useState([]);
  const [serverRows, setServerRows] = useState([]);

  const [userServers, setUserServers] = useState([]);

  const [rowsPerPageT1, setRowsPerPageT1] = React.useState(5);
  const [rowsPerPageT2, setRowsPerPageT2] = React.useState(10);
  const [pageT1, setPageT1] = React.useState(0);
  const [pageT2, setPageT2] = React.useState(0);
  const emptyRowsT1 = rowsPerPageT1 - Math.min(rowsPerPageT1, userServers.length - pageT1 * rowsPerPageT1);
  const emptyRowsT2 = rowsPerPageT2 - Math.min(rowsPerPageT2, servers.length - pageT2 * rowsPerPageT2);

  //const servercols: GridColDef[] = [
  const servercols = [
    { field: 'id', headerName: 'ID', width: 70, hide: true },
    { field: 'mint', headerName: 'Mint', width: 70, align: 'center', hide: true },
    { field: 'logo', headerName: '', width: 50, 
        renderCell: (params) => {
            //console.log(params);
            return (<>
                    <Avatar
                        sx={{backgroundColor:'#222'}}
                            src={
                                params.value}
                    >
                        {params.value}
                    </Avatar>
                
            </>);
        }
    },
    { field: 'name', headerName: 'Name', width: 350, flex: 1, 
      renderCell: (params) => {
        return (
          <>
          {params.value.name} <Tooltip title={`Visit ${params.value.name} Discord`}><Button href={`${params.value.url}`} target="_blank" sx={{color:'white',borderRadius:'17px',ml:1}}><DiscordIcon fontSize="small" /></Button></Tooltip>
          </>
        )
      },
      sortComparator: (v1, v2) => v1.name.localeCompare(v2.name)
    },
    { field: 'discordId', headerName: 'Discord ID', width: 130, hide: true },
    { field: 'discordUrl', headerName: 'Discord', width: 130, hide: true },
    { field: 'twitter', headerName: 'twitter', width: 130, hide: true },
    { field: 'gan', headerName: 'GAN', width: 130, align: 'center', headerAlign:'center', hide: true,
      renderCell: (params) => {
        return (
          <>
            {params.value ?
              <CheckCircleIcon />
            :
              <CircleOutlinedIcon sx={{ color: 'rgba(255,255,255,0.25)' }} />
            }
          </>
        )
      }
    },
    { field: 'registered', headerName: 'Registered', align: 'center', headerAlign:'center', width: 130, hide: false,
      renderCell: (params) => {
        return (
          <>
            {params.value ?
              <CheckCircleIcon />
            :
              <CircleOutlinedIcon sx={{ color: 'rgba(255,255,255,0.25)' }}/>
            }
          </>
        )
      }
    },
    { field: 'actions', headerName: 'Action', width: 130,  align: 'center', headerAlign:'center', flex: 0.3,
        renderCell: (params) => {
            return (
                <>
                  {params.value.registered ?
                    <Tooltip title={`Unregister ${params.value?.name}`}>
                      <Button color="error" size="small" variant="outlined" onClick={() => unregister(params.value.serverId, params.value.index)} sx={{mr:1}}><RemoveCircleOutlineIcon/></Button>
                    </Tooltip>
                  :
                    <Tooltip title={`Register ${params.value?.name}`}>
                      <Button color="primary" size="small" variant="contained" onClick={() => register(params.value.serverId)} sx={{mr:1}}><AddCircleOutlineIcon /></Button>
                    </Tooltip>
                  }
                </>
            )
        }
    }
  ];

  const register = async (serverId) => {
    //console.log("SESSION: "+JSON.stringify(session))
    //console.log("ServerId: "+JSON.stringify(serverId))

    const userServer = await UserServer.register(session, serverId);

    // update status of server rows
    for (var item of serverRows){
      if (item.serverId === serverId)
        item.registered = true;
        item.actions.registered = true;
    }

    session.userServers.push(userServer);
    setSession(session);
    setTab(0);
  };

  const unregister = async (serverId, index) => {
    const response = await UserServer.unregister(session, serverId);

    
    if (response) {
      let userServers = [...session.userServers];
      if (index){
        userServers.splice(index, 1);
        session.userServers = userServers;
        setSession(session);
        setUserServers(userServers);
        setServers(session.servers);
      }
      
      // update status of server rows
      for (var item of serverRows){
        if (item.serverId === serverId)
          item.registered = false;
          item.actions.registered = false;
      }
      
      
    }
  };

  useEffect(() => {
    let servers = session && session.servers;
    const userServers = session && session.userServers;

    if (servers && userServers) {
      let userServerIds = new Map();

      userServers.forEach(userServer => {
        userServerIds.set(userServer.serverId, true);
      });

      let newServers = servers.map(server => {
        server.registered = userServerIds.get(server.serverId) || false;

        return server;
      });

      const theseServers = new Array();

      //console.log("user servers: "+JSON.stringify(userServers))
      var counter = 0;
      for (var item of newServers){
        //console.log("item: "+JSON.stringify(item));
        
        var registered = false;
        for (var userver of userServers){
          if (userver.serverId === item.serverId)
            registered = true;
        }
        
        theseServers.push({
          id: item.serverId,
          mint: null,
          logo: 'https://verify.grapes.network/server-logos/'+item.logo,
          name: {
            name: item.name,
            url: item.url
          },
          discord: item.discordId,
          discordUrl: item.url,
          twitter: item.twitter,
          gan: item?.gan,
          registered: registered,
          actions: {
            serverId: item.serverId,
            name: item.name,
            registered: registered,
            index: null,//counter
          }
        });
        counter++;
      }

      var ucnt = 0;
      for (var i of userServers){
        for (var r of theseServers){
          if (i.serverId === r.id)
            r.actions.index = ucnt;
        }
        ucnt++;
      }
      const sortedResults = theseServers.sort((a,b) => (b.registered > a.registered) ? 1 : -1);
      setFullServerRows(sortedResults);
      setServerRows(sortedResults);

      setServers(newServers);
      setUserServers(userServers);
    }

  }, [session]);

  const filter = (keyword) => {
    //const keyword = e.target.value;
    if (keyword !== '') {
        const results = serverRows.filter((listitem) => {
          return listitem.name.name.toLowerCase().trim().includes(keyword.toLowerCase().trim())
        });
        setServerRows(results);
    } else {
      setServerRows(fullServerRows);
    }

    setFilterVal(keyword);
  }

  return (
    <React.Fragment>

      <Grid item xs={12} md={12} lg={12}>
        <Paper class="grape-paper-background">
            <Box
              class="grape-paper"
            >
              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                
                <CssTextField 
                  fullWidth
                  label="Find &amp; connect with communities" id="custom-css-outlined-input"
                  onChange={(e) => filter(e.target.value)}
                  //fvalue={filterVal}
                  sx={{ml:1.25,mr:1.25}} />
                
              </Box>
            </Box>
          </Paper>
        </Grid>
      

      <Grid item xs={12} md={12} lg={12}>
        <Paper class="grape-paper-background">
            <Box
              class="grape-paper"
            >
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <Box class="grape-dashboard-component-header" sx={{ m: 0, position: 'relative' }}>
                <Typography gutterBottom variant="h6" component="div" sx={{ m: 0, position: 'relative'}}>
                  SERVERS
                </Typography>
              </Box>
            </Box>
              <React.Fragment> 

                <Box sx={{mt:2,p:1}}>
                  <div style={{ height: 600, width: '100%' }}>
                    <div style={{ display: 'flex', height: '100%' }}>
                        <div style={{ flexGrow: 1 }}>
                          <DataGrid
                            rows={serverRows}
                            columns={servercols}
                            rowsPerPageOptions={[25, 50, 100, 250]}
                            sx={{
                                borderRadius:'17px',
                                borderColor:'rgba(255,255,255,0.25)',
                                '& .MuiDataGrid-cell':{
                                    borderColor:'rgba(255,255,255,0.25)'
                                }}}
                            //onSelectionModelChange={(newSelectionModel) => {
                            //    setSelectionModel(newSelectionModel);
                            //}}
                            initialState={{
                                sorting: {
                                    sortModel: [{ field: 'value', sort: 'desc' }],
                                },
                            }}
                            sortingOrder={['asc', 'desc', null]}
                            //checkboxSelection
                            disableSelectionOnClick
                        />
                        </div>
                      </div>
                    </div>

                </Box>
              
              </React.Fragment>
          </Box>
        </Paper>
      </Grid>
    </React.Fragment>
  );
}

export default ServersView;