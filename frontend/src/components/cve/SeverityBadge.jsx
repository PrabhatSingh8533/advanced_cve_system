import React from "react";
import { Chip } from "@mui/material";
import { getSeverityColor } from "../../theme";

export default function SeverityBadge({ severity, score }) {
  const color = getSeverityColor(severity);
  return (
    <Chip
      label={score ? `${severity || "N/A"} ${score}` : severity || "N/A"}
      size="small"
      sx={{ bgcolor: `${color}20`, color, border: `1px solid ${color}40`, fontWeight: 700, fontSize: "0.7rem" }}
    />
  );
}
