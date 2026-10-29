import React from "react";
import { AppBar, Toolbar, Typography, Box, Chip, IconButton, Tooltip } from "@mui/material";
import { Security, OpenInNew } from "@mui/icons-material";
import { Link, useLocation } from "react-router-dom";

const NAV_LINKS = [
  { path: "/", label: "Dashboard" },
  { path: "/cves", label: "CVE Search" },
  { path: "/predict", label: "AI Predict" },
  { path: "/analytics", label: "Analytics" },
  { path: "/collect", label: "Collect Data" },
];

export default function Navbar() {
  const location = useLocation();
  return (
    <AppBar position="fixed" sx={{ background: "rgba(15,23,42,0.95)", backdropFilter: "blur(10px)", borderBottom: "1px solid #334155", boxShadow: "none" }}>
      <Toolbar sx={{ gap: 1 }}>
        <Security sx={{ color: "#3b82f6", mr: 1 }} />
        <Typography variant="h6" sx={{ color: "#f1f5f9", fontWeight: 700, mr: 3, display: { xs: "none", md: "block" } }}>
          CVE Analysis System
        </Typography>
        <Box sx={{ display: "flex", gap: 0.5, flexGrow: 1, flexWrap: "wrap" }}>
          {NAV_LINKS.map(({ path, label }) => (
            <Link key={path} to={path} style={{ textDecoration: "none" }}>
              <Chip
                label={label}
                clickable
                variant={location.pathname === path ? "filled" : "outlined"}
                sx={{
                  borderColor: "#334155",
                  color: location.pathname === path ? "#fff" : "#94a3b8",
                  bgcolor: location.pathname === path ? "#3b82f6" : "transparent",
                  "&:hover": { bgcolor: location.pathname === path ? "#2563eb" : "#1e293b" },
                }}
              />
            </Link>
          ))}
        </Box>
        <Tooltip title="API Docs">
          <IconButton href="http://localhost:8000/docs" target="_blank" size="small" sx={{ color: "#94a3b8" }}>
            <OpenInNew fontSize="small" />
          </IconButton>
        </Tooltip>
      </Toolbar>
    </AppBar>
  );
}
