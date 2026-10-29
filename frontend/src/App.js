import React from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { ThemeProvider, CssBaseline, Box } from "@mui/material";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

import { theme } from "./theme";
import Navbar from "./components/layout/Navbar";
import Dashboard from "./pages/Dashboard";
import CVESearch from "./pages/CVESearch";
import AIPrediction from "./pages/AIPrediction";
import Analytics from "./pages/Analytics";
import CollectData from "./pages/CollectData";

export default function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <BrowserRouter>
        <Navbar />
        <Box sx={{ minHeight: "100vh", bgcolor: "background.default" }}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/cves" element={<CVESearch />} />
            <Route path="/predict" element={<AIPrediction />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/collect" element={<CollectData />} />
          </Routes>
        </Box>
        <ToastContainer
          position="bottom-right"
          theme="dark"
          autoClose={4000}
        />
      </BrowserRouter>
    </ThemeProvider>
  );
}
