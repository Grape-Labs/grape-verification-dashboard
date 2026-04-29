import * as React from 'react';
import MUIDataTable from "mui-datatables";

import {
  Grid,
  Typography,
  Table,
  Tooltip,
  Paper,
  Box,
  Avatar,
  LinearProgress,
} from '@mui/material';

import { LinearProgressProps } from '@mui/material/LinearProgress';
import { makeStyles, styled, alpha, useTheme } from '@mui/material/styles';

const StyledTable = styled(Table)(({ theme }) => ({
  '& .MuiTable-root': {
    background: 'none',
    tableLayout: 'fixed',
    borderCollapse: 'separate',
    borderSpacing: '0 16px',
  },
  '& .MuiPaper-root': {
    background: 'none',
    boxShadow: 'none',
  },
  '& .MuiToolbar-root': {
    '@media (min-width: 900px)': {
      height: '60px',
      minHeight: '60px !important',
      boxSizing: 'border-box',
    },
  },
  '& .MuiTableRow-root.MuiTableRow-head': {
    background: 'none',
    '& .MuiButton-root': {
      textTransform: 'uppercase',
      fontWeight: 'bold',
      fontSize: '0.75rem',
      marginLeft: '1px',
    },
    '&:hover': {
      background: 'none',
    },
  },
  '& .MuiTableCell-head:nth-child(1)': {
    width: '262px',
  },
  '& .MuiTableCell-head:nth-child(2)': {
    width: '211px',
  },
  '& .MuiTableCell-head:nth-child(6)': {
    width: '211px',
  },
  '& .MuiTableRow-root': {
    backgroundColor: 'transparent',
    '&:hover': {
      backgroundColor: 'transparent',
    },
  },
  '& .MuiTableCell-root': {
    background: 'none',
    borderBottom: 'none',
    '@media (min-width: 900px)': {
      height: '60px',
      minHeight: '60px !important',
      boxSizing: 'border-box',
    },
  },
  '& .MuiTableCell-root.MuiTableCell-body': {
    lineHeight: '1.25em',
    fontSize: '1rem',
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
    padding: '1rem',
    '&:hover': {
      backgroundColor: 'rgba(0, 0, 0, 0.5)',
    },
    '@media (min-width: 900px)': {
      padding: 0,
    },
  },
  '& .MuiTableCell-root.MuiTableCell-body:first-child': {
    '@media (min-width: 900px)': {
      borderTopLeftRadius: '60px',
      borderBottomLeftRadius: '60px',
    },
  },
  '& .MuiTableCell-root.MuiTableCell-body:last-child': {
    '@media (min-width: 900px)': {
      borderTopRightRadius: '60px',
      borderBottomRightRadius: '60px',
    },
  },
  '& .MuiTableCell-root.MuiTableCell-head': {
    lineHeight: '1.25em',
    textTransform: 'uppercase',
    padding: 0,
  },
  '& .MuiAvatar-circular.MuiPaper-root': {
    background: '#333',
  },
}));

const numberFormater = new Intl.NumberFormat('en-US', {
  style: 'decimal',
  minimumFractionDigits: 0,
  maximumFractionDigits: 2,
});

export const formatNumber = {
  format: (val) => {
    if (!val) {
      return '--';
    }

    return numberFormater.format(val);
  },
};

function LinearProgressWithLabel(props) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', width: '100%', pr: 2 }}>
      <Box sx={{ width: '100%', height: '1rem' }}>
        <LinearProgress
          sx={{
            height: '1rem',
            borderTopLeftRadius: '1rem',
            borderBottomLeftRadius: '1rem',
            '& .MuiLinearProgress-bar': {
              background:
                'linear-gradient(276deg, #0FE2DF 5.96%, #8870F2 86.08%, #9E5BF6 96.45%)',
              borderRadius: '1rem',
            },
          }}
          variant="determinate"
          {...props}
        />
      </Box>
      <Box
        sx={{
          minWidth: 50,
          backgroundColor: 'black',
          textAlign: 'center',
          p: 1,
          borderRadius: 1,
        }}
      >
        <Typography variant="body2" sx={{ color: 'text.secondary' }}>
          {`${Math.round(props.value)}%`}
        </Typography>
      </Box>
    </Box>
  );
}

export function GrapePartnersView(props) {
  //const [partnerData, setPartnerData] = React.useEffect(null);
  const partnercolumns = [
    {
      name:"name",
      label:"Collection",
      options: {
        filter: true,
        sort: true,
        display: true,
        customBodyRender: (value, tableMeta, updateValue) => {
          //console.log(tableMeta.rowData, '......');
          return (
            <Grid container direction="row" alignItems="center">
              <Grid item>
                <Avatar component={Paper} 
                    elevation={4}
                    alt={tableMeta.rowData[0]}
                    src={`${tableMeta.rowData[1]}`}
                    sx={{
                      width: 60,
                      height: 60,
                    }}
                />
              </Grid>
              <Grid item>
                <Typography sx={{ marginLeft: 0, whiteSpace: 'pre-wrap', lineHeight: 1.25, p: 1 }}>
                  {tableMeta.rowData[0].length > 20 ?
                    tableMeta.rowData[0].substring(0,18) + '...'
                  :
                    tableMeta.rowData[0]
                  }
                </Typography>
              </Grid>
            </Grid>
          );
        },
        setCellHeaderProps: () => ({
          align: "center"
        })
      }
    },
    {
      name:"image",
      label:"Image",
      options: {
        filter: false,
        sort: false,
        display: false,
       }
    },
    {
      name:"community_strength",
      label:"Community Strength",
      options: {
        filter: false,
        sort: true,
        display: true,
        customBodyRender: (value, tableMeta, updateValue) => {
          return <LinearProgressWithLabel value={tableMeta.rowData[2]} />;
        },
        setCellHeaderProps: () => ({
          align: "center"
        })
       }
    },
    {
      name:"nft_average",
      label:"NFT Average",
      options: {
        filter: false,
        sort: true,
        display: true,
        customBodyRender: (value, tableMeta, updateValue) => {
          return (
            formatNumber.format(tableMeta.rowData[3])
          );
        },
        setCellProps: () => ({
          align: "center"
        }),
        setCellHeaderProps: () => ({
          align: "center"
        })
      }
    },
    {
      name:"unique_holders", 
      label:"Unique Holders",
      options: {
        filter: false,
        sort: true,
        display: true,
        customBodyRender: (value, tableMeta, updateValue) => {
          return (
            formatNumber.format(tableMeta.rowData[4])
          );
        },
        setCellProps: () => ({
          align: "center"
        }),
        setCellHeaderProps: () => ({
          align: "center"
        })
      }
    },
    {
      name:"grape_holder_score",
      label:"Grape Holder Score",
      options: {
        filter: false,
        sort: true,
        display: true,
        customBodyRender: (value, tableMeta, updateValue) => {
          return <LinearProgressWithLabel value={tableMeta.rowData[5]} />;
        },
        setCellHeaderProps: () => ({
          align: "center"
        })
      }
    }
  ];

  const partnerdatastatic = [
    {
      "name": "Shadowy Super Coder",
      "image": "https://verify.grapedao.org/server-logos/genesysgo.png",
      "community_strength": 47,
      "tvl": 28197,
      "nft_average": 3,
      "unique_holders": 1821,
      "grape_holder_score": 49
    },
    {
      "name": "Turtles",
      "image": "https://nznh6xujkvtqqg2yph63lm4d7nh2j62qacaxl5irbzcgf3abbnfa.arweave.net/blp_XolVZwgbWHn9tbOD-0-k-1AAgXX1EQ5EYuwBC0o/?ext=png",
      "community_strength": 65,
      "tvl": 15096,
      "nft_average": 2,
      "unique_holders": 984,
      "grape_holder_score": 62
    },
    {
      "name": "DEGEN DAOO",
      "image": "https://verify.grapedao.org/server-logos/degendaoo.png",
      "community_strength": 32,
      "tvl": 8196,
      "nft_average": 2,
      "unique_holders": 1506,
      "grape_holder_score": 36
    },
    {
      "name": "Boryoku Dragonz",
      "image": "https://verify.grapedao.org/server-logos/boryoku.png",
      "community_strength": 66,
      "tvl": 5545,
      "nft_average": 2,
      "unique_holders": 215,
      "grape_holder_score": 69
    },
    {
      "name": "Solarians",
      "image": "https://verify.grapedao.org/server-logos/solarians.gif",
      "community_strength": 29,
      "tvl": 6391,
      "nft_average": 3,
      "unique_holders": 811,
      "grape_holder_score": 27
    },
    {
      "name": "MonkeDAO",
      "image": "https://verify.grapedao.org/server-logos/monkedao.png",
      "community_strength": 51,
      "tvl": 3954,
      "nft_average": 2,
      "unique_holders": 803,
      "grape_holder_score": 70
    },
    {
      "name": "thugDAO",
      "image": "https://verify.grapedao.org/server-logos/thugbirdz.png",
      "community_strength": 62,
      "tvl": 3667,
      "nft_average": 1,
      "unique_holders": 1299,
      "grape_holder_score": 71
    },
    {
      "name": "Lifinity",
      "image": "https://verify.grapedao.org/server-logos/lifinity.png",
      "community_strength": 44,
      "tvl": 791,
      "nft_average": 6,
      "unique_holders": 1242,
      "grape_holder_score": 42
    }
  ];

  const partneroptions = {
    selectableRows: false,
    download:false,
    print:false,
    viewColumns:false,
    filter:false
  };
  
  const getPartnerData=()=>{ // this function will be used later on
    fetch('dataRaw.json'
    ,{
      headers : { 
        'Content-Type': 'application/json',
        'Accept': 'application/json'
       }
    }
    )
      .then(function(response){
        console.log(response)
        return response.json();
      })
      .then(function(myJson) {
        console.log(myJson);
      });
  }

  React.useEffect(()=>{
    //setPartnerData(getPartnerData()); // we will fetch dynamically later on
  },[])


  return (
    <>
      <Box sx={{ p: 2, textAlign: 'center' }}>
        <Typography 
          variant="h5"
          sx={{ marginLeft: 0, whiteSpace: 'pre-wrap', lineHeight: 1.25, p: 1 }}>
          PARTNER REPORT
        </Typography>
      </Box>
      <StyledTable sx={{ minWidth: 500 }} size="small" aria-label="Grape Partners Table">
        <MUIDataTable
          title={""}
          data={partnerdatastatic}
          columns={partnercolumns}
          options={partneroptions}
        />
      </StyledTable>
      <Box sx={{ p: 2, textAlign: 'center' }}>
        <Typography variant="caption">
          <Grid container align="center" xs={{textAlign: 'center'}}>
            <Grid item xs={12}>* Percentage of total NFTs held by the community</Grid>
            <Grid item xs={12}>** The current floor price * number of NFTs held by community</Grid>
            <Grid item xs={12}>*** Percentage of verified holders against overall holders who are members of the community</Grid>
          </Grid>
        </Typography>
      </Box>
    </>
  );
}
