import React from "react";
import { Card, CardContent, Typography, Box, Skeleton } from "@mui/material";

export default function StatCard({ title, value, subtitle, icon: Icon, color = "#3b82f6", loading = false }) {
  return (
    <Card sx={{ height: "100%" }}>
      <CardContent>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <Box>
            <Typography variant="body2" sx={{ color: "#94a3b8", mb: 1 }}>
              {title}
            </Typography>
            {loading ? (
              <Skeleton width={120} height={40} />
            ) : (
              <Typography variant="h4" sx={{ color, fontWeight: 700 }}>
                {value}
              </Typography>
            )}
            {subtitle && (
              <Typography variant="caption" sx={{ color: "#64748b" }}>
                {subtitle}
              </Typography>
            )}
          </Box>
          {Icon && (
            <Box sx={{ bgcolor: `${color}20`, borderRadius: 2, p: 1, display: "flex" }}>
              <Icon sx={{ color, fontSize: 28 }} />
            </Box>
          )}
        </Box>
      </CardContent>
    </Card>
  );
}
