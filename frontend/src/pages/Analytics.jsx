import React, { useState } from "react";
import {
  Box, Typography, Grid, Card, CardContent,
  Tab, Tabs, Chip, CircularProgress,
  Table, TableBody, TableCell,
  TableHead, TableRow, Alert
} from "@mui/material";
import {
  TrendingUp, TrendingDown, Remove,
  BugReport, Computer, Assessment
} from "@mui/icons-material";
import PlotlyChart from "../components/charts/PlotlyChart";
import { useApi } from "../hooks/useApi";
import { analyticsApi } from "../services/api";

// ── Small helper components ───────────────────────────────
function GrowthChip({ pct }) {
  if (pct === null || pct === undefined || pct === 0) {
    return <Chip icon={<Remove sx={{ fontSize: 14 }} />}
      label="0.0%" size="small"
      sx={{ bgcolor: "#1e293b", color: "#64748b", fontSize: "0.7rem" }} />;
  }
  const positive = pct > 0;
  return (
    <Chip
      icon={positive
        ? <TrendingUp sx={{ fontSize: 14 }} />
        : <TrendingDown sx={{ fontSize: 14 }} />}
      label={`${positive ? "+" : ""}${Number(pct).toFixed(1)}%`}
      size="small"
      sx={{
        bgcolor: positive ? "#14532d30" : "#7f1d1d30",
        color: positive ? "#22c55e" : "#ef4444",
        border: `1px solid ${positive ? "#22c55e40" : "#ef444440"}`,
        fontSize: "0.7rem"
      }}
    />
  );
}

function SectionHeader({ icon: Icon, title, subtitle, color = "#3b82f6" }) {
  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 3 }}>
      <Box sx={{ bgcolor: `${color}20`, borderRadius: 2, p: 1, display: "flex" }}>
        <Icon sx={{ color, fontSize: 24 }} />
      </Box>
      <Box>
        <Typography variant="h6" sx={{ fontWeight: 700 }}>{title}</Typography>
        {subtitle && <Typography variant="caption" color="text.secondary">{subtitle}</Typography>}
      </Box>
    </Box>
  );
}

// ── Tab 1: Overview ───────────────────────────────────────
function OverviewTab() {
  const { data, loading, error } = useApi(analyticsApi.overview);

  if (loading) return (
    <Box sx={{ display: "flex", justifyContent: "center", p: 6 }}>
      <CircularProgress />
    </Box>
  );

  if (error) return (
    <Alert severity="error" sx={{ m: 2 }}>Error: {error}</Alert>
  );

  const yoy = data?.yoy_growth || [];

  return (
    <Box>
      {/* Summary Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        {[
          {
            label: "Total CVEs Analyzed",
            value: data?.summary?.total_cves?.toLocaleString() || "—",
            color: "#3b82f6"
          },
          {
            label: "Monthly Average",
            value: data?.summary?.monthly_avg?.toLocaleString() || "—",
            color: "#8b5cf6"
          },
          {
            label: "Period",
            value: `${data?.summary?.date_range?.start?.slice(0,4) || "—"} - ${data?.summary?.date_range?.end?.slice(0,4) || "—"}`,
            color: "#06b6d4"
          },
          {
            label: "Anomalies Found",
            value: data?.anomalies_detected ?? "—",
            color: "#f97316"
          },
        ].map(({ label, value, color }) => (
          <Grid item xs={6} sm={3} key={label}>
            <Card>
              <CardContent sx={{ py: 2 }}>
                <Typography variant="caption" color="text.secondary">{label}</Typography>
                <Typography variant="h5" sx={{ color, fontWeight: 700, mt: 0.5 }}>
                  {value}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* YoY Growth Table */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <SectionHeader
            icon={TrendingUp}
            title="Year-over-Year CVE Growth"
            subtitle="Annual CVE publication counts and growth rates from NVD"
          />
          <Box sx={{ overflowX: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  {["Year", "Total CVEs", "Previous Year", "Change", "Growth %"].map(h => (
                    <TableCell key={h} sx={{
                      color: "#64748b", fontWeight: 700,
                      borderBottom: "1px solid #334155",
                      fontSize: "0.75rem"
                    }}>{h}</TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {yoy.map((row) => (
                  <TableRow key={row.year}
                    sx={{ "&:hover": { bgcolor: "#1e293b" } }}>
                    <TableCell sx={{ color: "#3b82f6", fontWeight: 700, borderBottom: "1px solid #1e293b" }}>
                      {row.year}
                    </TableCell>
                    <TableCell sx={{ color: "#f1f5f9", borderBottom: "1px solid #1e293b" }}>
                      {row.total?.toLocaleString() || "—"}
                    </TableCell>
                    <TableCell sx={{ color: "#94a3b8", borderBottom: "1px solid #1e293b" }}>
                      {row.prev_year_total > 0
                        ? row.prev_year_total?.toLocaleString()
                        : "—"}
                    </TableCell>
                    <TableCell sx={{ borderBottom: "1px solid #1e293b" }}>
                      <Typography variant="body2" sx={{
                        color: row.yoy_change > 0 ? "#22c55e" : row.yoy_change < 0 ? "#ef4444" : "#64748b",
                        fontWeight: 600, fontSize: "0.8rem"
                      }}>
                        {row.yoy_change > 0 ? "+" : ""}{row.yoy_change?.toLocaleString() || "—"}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ borderBottom: "1px solid #1e293b" }}>
                      <GrowthChip pct={row.yoy_growth_pct} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Box>

          {/* Anomalies */}
          {data?.anomalies?.length > 0 && (
            <Box sx={{ mt: 3 }}>
              <Typography variant="subtitle2" sx={{ color: "#f97316", mb: 1 }}>
                ⚠️ Anomalous Months Detected
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                {data.anomalies.map((a) => (
                  <Chip
                    key={a.date}
                    label={`${a.date}: ${a.total_cves?.toLocaleString()} CVEs (${a.direction})`}
                    size="small"
                    sx={{
                      bgcolor: a.direction === "spike" ? "#7f1d1d30" : "#1c1a00",
                      color: a.direction === "spike" ? "#ef4444" : "#eab308",
                      border: `1px solid ${a.direction === "spike" ? "#ef444440" : "#eab30840"}`,
                      fontSize: "0.65rem"
                    }}
                  />
                ))}
              </Box>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Monthly Chart */}
      <MonthlyChartSection />
    </Box>
  );
}

function MonthlyChartSection() {
  const { data, loading } = useApi(analyticsApi.monthlyChart);
  return (
    <Card>
      <CardContent>
        <SectionHeader
          icon={Assessment}
          title="Monthly CVE Count Trend"
          subtitle="Monthly publication counts with 12-month rolling average"
        />
        <PlotlyChart chartData={data} loading={loading} height={400} />
      </CardContent>
    </Card>
  );
}

// ── Tab 2: RCE & Severity ─────────────────────────────────
function ThreatTab() {
  const { data: rce, loading: rL } = useApi(analyticsApi.rce);
  const { data: sev, loading: sL } = useApi(analyticsApi.severityChart);

  return (
    <Box>
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <SectionHeader
                icon={BugReport}
                title="Remote Code Execution (RCE) Trend"
                subtitle="Monthly RCE count and percentage of total CVEs"
                color="#dc2626"
              />
              {rce && (
                <Grid container spacing={2} sx={{ mb: 2 }}>
                  {[
                    { label: "Total RCE CVEs", value: rce.total_rce_cves?.toLocaleString(), color: "#dc2626" },
                    { label: "Avg % of Total", value: `${rce.average_rce_percentage?.toFixed(1)}%`, color: "#f97316" },
                    { label: "Trend", value: rce.trend_direction, color: "#eab308" },
                  ].map(({ label, value, color }) => (
                    <Grid item xs={4} key={label}>
                      <Box sx={{ bgcolor: "#0f172a", borderRadius: 2, p: 2, border: `1px solid ${color}30`, textAlign: "center" }}>
                        <Typography variant="h6" sx={{ color, fontWeight: 700 }}>{value}</Typography>
                        <Typography variant="caption" color="text.secondary">{label}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              )}
              <PlotlyChart chartData={rce?.chart} loading={rL} height={320} />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Card>
            <CardContent>
              <SectionHeader
                icon={Assessment}
                title="Severity Distribution Over Time"
                subtitle="How CRITICAL/HIGH/MEDIUM/LOW CVEs evolved annually"
                color="#8b5cf6"
              />
              <PlotlyChart chartData={sev} loading={sL} height={350} />
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}

// ── Tab 3: OS Analysis ────────────────────────────────────
function OSTab() {
  const { data, loading } = useApi(analyticsApi.os);

  return (
    <Box>
      <Card>
        <CardContent>
          <SectionHeader
            icon={Computer}
            title="Vulnerability Distribution by OS/Platform"
            subtitle="Which platforms have the most CVEs"
            color="#06b6d4"
          />
          {data?.top_platforms && (
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {Object.entries(data.top_platforms).slice(0, 4).map(([os, count]) => (
                <Grid item xs={6} sm={3} key={os}>
                  <Box sx={{ bgcolor: "#0f172a", borderRadius: 2, p: 2, border: "1px solid #334155", textAlign: "center" }}>
                    <Typography variant="h6" sx={{ color: "#06b6d4", fontWeight: 700 }}>
                      {Number(count).toLocaleString()}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">{os}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          )}
          <PlotlyChart chartData={data?.chart} loading={loading} height={420} />
        </CardContent>
      </Card>
    </Box>
  );
}

// ── Tab 4: Forecast ───────────────────────────────────────
function ForecastTab() {
  const { data, loading, error } = useApi(
    () => analyticsApi.forecast(12)
  );

  const fc = data?.arima_forecast || {};
  const exp = data?.exp_smoothing_forecast || {};

  return (
    <Box>
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <SectionHeader
            icon={TrendingUp}
            title="12-Month CVE Count Forecast"
            subtitle={`Method: ${fc.method || "Loading..."} • Confidence interval: 95%`}
            color="#06b6d4"
          />

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              Forecast error: {error}
            </Alert>
          )}

          {/* Forecast chart */}
          <PlotlyChart
            chartData={data?.chart}
            loading={loading}
            height={420}
          />

          {/* Forecast values table */}
          {fc.dates && fc.dates.length > 0 && (
            <Box sx={{ mt: 3, overflowX: "auto" }}>
              <Typography variant="subtitle2" sx={{ mb: 1.5, color: "#94a3b8" }}>
                📋 Monthly Forecast Values
              </Typography>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    {["Month", "ARIMA Forecast", "Lower 95%", "Upper 95%", "Exp. Smoothing"].map(h => (
                      <TableCell key={h} sx={{
                        color: "#64748b", fontWeight: 700,
                        borderBottom: "1px solid #334155",
                        fontSize: "0.72rem"
                      }}>{h}</TableCell>
                    ))}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {fc.dates.map((date, i) => (
                    <TableRow key={date} sx={{ "&:hover": { bgcolor: "#1e293b" } }}>
                      <TableCell sx={{ color: "#06b6d4", fontWeight: 600, borderBottom: "1px solid #1e293b", fontSize: "0.8rem" }}>
                        {date}
                      </TableCell>
                      <TableCell sx={{ color: "#f1f5f9", borderBottom: "1px solid #1e293b", fontSize: "0.8rem" }}>
                        {fc.values?.[i]?.toLocaleString() || "—"}
                      </TableCell>
                      <TableCell sx={{ color: "#22c55e", borderBottom: "1px solid #1e293b", fontSize: "0.8rem" }}>
                        {fc.lower_95?.[i]?.toLocaleString() || "—"}
                      </TableCell>
                      <TableCell sx={{ color: "#f97316", borderBottom: "1px solid #1e293b", fontSize: "0.8rem" }}>
                        {fc.upper_95?.[i]?.toLocaleString() || "—"}
                      </TableCell>
                      <TableCell sx={{ color: "#8b5cf6", borderBottom: "1px solid #1e293b", fontSize: "0.8rem" }}>
                        {exp.values?.[i]?.toLocaleString() || "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Heatmap */}
      <HeatmapSection />
    </Box>
  );
}

function HeatmapSection() {
  const { data, loading } = useApi(analyticsApi.heatmap);
  return (
    <Card>
      <CardContent>
        <SectionHeader
          icon={Assessment}
          title="Exploit Type Heatmap by Year"
          subtitle="How different attack types evolved from 2015-2024"
          color="#f97316"
        />
        <PlotlyChart chartData={data} loading={loading} height={380} />
      </CardContent>
    </Card>
  );
}

// ── Main Analytics Page ───────────────────────────────────
export default function Analytics() {
  const [tab, setTab] = useState(0);

  const tabs = [
    { label: "📈 Overview & YoY", component: <OverviewTab /> },
    { label: "🔴 RCE & Severity", component: <ThreatTab /> },
    { label: "💻 OS Distribution", component: <OSTab /> },
    { label: "🔮 Forecast", component: <ForecastTab /> },
  ];

  return (
    <Box sx={{ p: 3, pt: 10 }}>
      <Typography variant="h4" sx={{ fontWeight: 700, mb: 0.5 }}>
        Temporal Trend Analysis
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        CVE time-series analysis • ARIMA forecasting • Threat intelligence
      </Typography>

      <Tabs
        value={tab}
        onChange={(_, v) => setTab(v)}
        sx={{
          mb: 3,
          borderBottom: "1px solid #334155",
          "& .MuiTab-root": { color: "#64748b", fontSize: "0.85rem" },
          "& .Mui-selected": { color: "#3b82f6 !important" },
          "& .MuiTabs-indicator": { bgcolor: "#3b82f6" },
        }}
      >
        {tabs.map(({ label }) => (
          <Tab key={label} label={label} />
        ))}
      </Tabs>

      {tabs[tab].component}
    </Box>
  );
}

