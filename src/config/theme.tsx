import { createTheme } from '@mui/material/styles';

const fontFamily = [
  'Gilroy',
  'ui-sans-serif',
  'system-ui',
  '-apple-system',
  'BlinkMacSystemFont',
  '"Segoe UI"',
  'sans-serif',
].join(',');

const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#f1c96b',
      light: '#ffe2a2',
      dark: '#b78930',
    },
    secondary: {
      main: '#7ee7d8',
      light: '#b4fff2',
      dark: '#42b7a4',
    },
    background: {
      default: '#07111f',
      paper: '#0d1727',
    },
    text: {
      primary: '#f6f1e8',
      secondary: 'rgba(246, 241, 232, 0.72)',
    },
    divider: 'rgba(255,255,255,0.08)',
  },
  shape: {
    borderRadius: 18,
  },
  typography: {
    fontFamily,
    h3: {
      fontWeight: 800,
      letterSpacing: '-0.04em',
    },
    h6: {
      fontWeight: 700,
      letterSpacing: '-0.02em',
    },
    subtitle1: {
      fontWeight: 700,
    },
    button: {
      fontWeight: 700,
      textTransform: 'none',
      letterSpacing: '0.01em',
    },
  },
  components: {
    MuiAppBar: {
      styleOverrides: {
        root: {
          background: 'rgba(6, 12, 22, 0.68)',
          backdropFilter: 'blur(22px)',
          borderBottom: '1px solid rgba(255,255,255,0.06)',
          boxShadow: 'none',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 999,
          paddingInline: 18,
        },
        containedPrimary: {
          color: '#1a1304',
          background: 'linear-gradient(135deg, #f1c96b 0%, #dca94b 100%)',
          boxShadow: '0 14px 40px rgba(220, 169, 75, 0.18)',
        },
        outlined: {
          borderColor: 'rgba(255,255,255,0.14)',
        },
      },
    },
    MuiTabs: {
      styleOverrides: {
        indicator: {
          height: 3,
          borderRadius: 999,
          backgroundColor: '#f1c96b',
        },
      },
    },
    MuiTab: {
      styleOverrides: {
        root: {
          minHeight: 56,
          fontWeight: 700,
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: {
          borderColor: 'rgba(255,255,255,0.08)',
        },
      },
    },
  },
});

export default theme;
