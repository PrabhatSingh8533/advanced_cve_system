import React, { useState } from "react";
import { Card, CardContent, Typography, Box, Chip, IconButton, Tooltip } from "@mui/material";
import { ExpandMore, ExpandLess, ContentCopy } from "@mui/icons-material";
import SeverityBadge from "./SeverityBadge";
import { toast } from "react-toastify";

export default function CVECard({ cve }) {
  const [expanded, setExpanded] = useState(false);
  const copyId = () => { navigator.clipboard.writeText(cve.cve_id); toast.success(`Copied ${cve.cve_id}`); };
  return (
    <Card sx={{ mb: 1.5, border: "1px solid #334155", "&:hover": { borderColor: "#3b82f6", transform: "translateY(-1px)", transition: "all 0.2s" } }}>
      <CardContent sx={{ pb: "12px !important" }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, flexWrap: "wrap" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <Typography variant="subtitle2" sx={{ color: "#3b82f6", fontWeight: 700, fontFamily: "monospace" }}>
              {cve.cve_id}
            </Typography>
            <Tooltip title="Copy ID">
              <IconButton size="small" onClick={copyId} sx={{ p: 0.2 }}>
                <ContentCopy sx={{ fontSize: 12, color: "#64748b" }} />
              </IconButton>
            </Tooltip>
          </Box>
          <SeverityBadge severity={cve.severity} score={cve.cvss_score} />
          {cve.exploit_type && <Chip label={cve.exploit_type} size="small" sx={{ bgcolor: "#1e293b", color: "#94a3b8", border: "1px solid #334155", fontSize: "0.65rem" }} />}
          {cve.cwe_code && <Chip label={cve.cwe_code} size="small" sx={{ bgcolor: "#312e81", color: "#a5b4fc", fontSize: "0.65rem" }} />}
          <Typography variant="caption" sx={{ color: "#64748b", ml: "auto" }}>{cve.published_date || "N/A"}</Typography>
        </Box>
        <Typography variant="body2" sx={{ color: "#cbd5e1", fontSize: "0.82rem", lineHeight: 1.5, display: "-webkit-box", WebkitLineClamp: expanded ? "unset" : 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>
          {cve.description}
        </Typography>
        {cve.description?.length > 150 && (
          <Box sx={{ display: "flex", justifyContent: "flex-end", mt: 0.5 }}>
            <IconButton size="small" onClick={() => setExpanded(!expanded)} sx={{ color: "#64748b", p: 0.3 }}>
              {expanded ? <ExpandLess fontSize="small" /> : <ExpandMore fontSize="small" />}
            </IconButton>
          </Box>
        )}
      </CardContent>
    </Card>
  );
}
