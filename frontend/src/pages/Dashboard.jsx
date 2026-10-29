import React from "react";
import { Grid, Typography, Box, Card, CardContent, LinearProgress } from "@mui/material";
import { BugReport, Warning, Storage, TrendingUp } from "@mui/icons-material";
import StatCard from "../components/layout/StatCard";
import PlotlyChart from "../components/charts/PlotlyChart";
import CVECard from "../components/cve/CVECard";
import { useApi } from "../hooks/useApi";
import { cveApi, analyticsApi } from "../services/api";

export default function Dashboard() {
  const { data: stats, loading: sL } = useApi(cveApi.stats);
  const { data: recent } = useApi(() => cveApi.recent(7, 5));
  const { data: sevChart, loading: scL } = useApi(analyticsApi.severityChart);
  const { data: rce, loading: rL } = useApi(analyticsApi.rce);

  return (
    <Box sx={{ p: 3, pt: 10 }}>
      <Typography variant="h4" sx={{ fontWeight: 700, mb: 0.5 }}>CVE Analysis Dashboard</Typography>
      

      <Grid container spacing={2} sx={{ mb: 3 }}>
        {[
          { title: "Total CVEs", value: stats?.total_cves?.toLocaleString() || "â€”", icon: Storage, color: "#3b82f6", sub: "In database" },
          { title: "Critical", value: stats?.severity_distribution?.CRITICAL?.toLocaleString() || "â€”", icon: Warning, color: "#dc2626", sub: "CVSS â‰¥ 9.0" },
          { title: "High", value: stats?.severity_distribution?.HIGH?.toLocaleString() || "â€”", icon: BugReport, color: "#f97316", sub: "CVSS 7-8.9" },
          { title: "Avg CVSS", value: stats?.average_cvss_score || "â€”", icon: TrendingUp, color: "#8b5cf6", sub: "Average score" },
        ].map((s) => (
          <Grid item xs={6} sm={3} key={s.title}>
            <StatCard {...s} loading={sL} />
          </Grid>
        ))}
      </Grid>

      <Grid container spacing={2}>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>Severity Distribution Over Time</Typography>
              <PlotlyChart chartData={sevChart} loading={scL} height={320} />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card sx={{ height: "100%" }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>Top Exploit Types</Typography>
              {stats?.top_exploit_types?.slice(0, 7).map((item, i) => {
                const max = stats.top_exploit_types[0]?.count || 1;
                return (
                  <Box key={i} sx={{ mb: 1.5 }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.3 }}>
                      <Typography variant="caption" sx={{ color: "#cbd5e1", fontSize: "0.72rem" }}>{item.type}</Typography>
                      <Typography variant="caption" sx={{ color: "#64748b" }}>{item.count?.toLocaleString()}</Typography>
                    </Box>
                    <LinearProgress variant="determinate" value={(item.count / max) * 100}
                      sx={{ height: 4, borderRadius: 2, bgcolor: "#1e293b", "& .MuiLinearProgress-bar": { bgcolor: i === 0 ? "#dc2626" : i === 1 ? "#f97316" : "#3b82f6" } }} />
                  </Box>
                );
              })}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={7}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>RCE Attack Trend</Typography>
              <PlotlyChart chartData={rce?.chart} loading={rL} height={280} />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={5}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>Recent CVEs (7 days)</Typography>
              {recent?.items?.slice(0, 4).map((cve) => <CVECard key={cve.id} cve={cve} />)}
              {recent?.items?.length === 0 && <Typography color="text.secondary" variant="body2">No recent CVEs. Collect data first.</Typography>}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
