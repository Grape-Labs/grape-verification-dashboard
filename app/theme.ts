// app/theme.ts
"use client";

import { createTheme } from "@mui/material/styles";

export const theme = createTheme({
  palette: {
    mode: "dark",
    background: {
      default: "#070A12", // deep ink
      paper: "rgba(18, 22, 38, 0.78)", // panel glass
    },
    text: {
      primary: "rgba(255,255,255,0.92)",
      secondary: "rgba(255,255,255,0.68)",
    },
    primary: { main: "#26C6FF" },   // neon cyan
    secondary: { main: "#7C4DFF" }, // grape purple
    warning: { main: "#FFD400" },   // comic yellow
    success: { main: "#46E6A5" },
    error: { main: "#FF4D6D" },
  },

  shape: { borderRadius: 18 },

  typography: {
    // You already import Bangers + Roboto Mono in Providers
    fontFamily: [
      "Bangers",
      "ui-sans-serif",
      "system-ui",
      "-apple-system",
      "Segoe UI",
      "Roboto",
      "Arial",
      "sans-serif",
    ].join(","),
    h1: { fontWeight: 400, letterSpacing: 1.2 },
    h2: { fontWeight: 400, letterSpacing: 1.0 },
    h3: { fontWeight: 400, letterSpacing: 0.8 },
    button: { fontWeight: 900, letterSpacing: 0.4 },
    body1: { fontFamily: "system-ui" },
    body2: { fontFamily: "system-ui" },
  },

  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          // nice comic background globally (you can still override per-page)
          background:
            "radial-gradient(1200px 600px at 15% 0%, rgba(124,77,255,0.22), transparent 60%)," +
            "radial-gradient(900px 500px at 90% 10%, rgba(38,198,255,0.18), transparent 55%)," +
            "radial-gradient(circle at 1px 1px, rgba(255,255,255,0.06) 1px, rgba(0,0,0,0) 1.6px)," +
            "linear-gradient(180deg, #070A12, #050610)",
          backgroundSize: "auto, auto, 12px 12px, auto",
        },
      },
    },

    MuiPaper: {
      styleOverrides: {
        root: {
          border: "3px solid #0B1220",
          boxShadow: "6px 6px 0 #0B1220",
          backgroundImage:
            "linear-gradient(180deg, rgba(255,255,255,0.08), rgba(255,255,255,0.00))",
          backdropFilter: "blur(10px)",
        },
      },
    },

    MuiChip: {
      styleOverrides: {
        root: {
          border: "2px solid #0B1220",
          boxShadow: "3px 3px 0 #0B1220",
          fontWeight: 900,
          background: "rgba(255,255,255,0.08)",
        },
      },
    },

    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 16,
          border: "2px solid #0B1220",
          boxShadow: "4px 4px 0 #0B1220",
          textTransform: "none",
          fontWeight: 900,
        },
        contained: {
          backgroundImage:
            "linear-gradient(180deg, rgba(255,255,255,0.20), rgba(255,255,255,0.00))",
        },
      },
    },

    MuiDivider: {
      styleOverrides: {
        root: { borderColor: "rgba(255,255,255,0.14)" },
      },
    },
  },
});