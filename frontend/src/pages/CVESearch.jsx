import React, { useState } from "react";
import {
  Box, Typography, TextField, Grid, Card, CardContent,
  Select, MenuItem, FormControl, InputLabel,
  Button, Chip, CircularProgress, Pagination, Alert
} from "@mui/material";
import { Search, FilterList, Clear } from "@mui/icons-material";
import CVECard from "../components/cve/CVECard";
import { cveApi } from "../services/api";
import { useApi } from "../hooks/useApi";

const SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEV_COLORS = {
  CRITICAL: "#dc2626", HIGH: "#f97316",
  MEDIUM: "#eab308", LOW: "#22c55e"
};

export default function CVESearch() {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("");
  const [minCvss, setMinCvss] = useState("");
  const [year, setYear] = useState("");
  const [page, setPage] = useState(1);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const { data: stats } = useApi(cveApi.stats);

  const handleSearch = async (p = 1) => {
    setLoading(true);
    setError(null);
    try {
      let data;
      if (query.trim().length >= 2) {
        data = await cveApi.search(query.trim(), p, 15);
      } else {
        data = await cveApi.list({
          severity: severity || undefined,
          min_cvss: minCvss || undefined,
          year: year || undefined,
          page: p,
          page_size: 15,
        });
      }
      setResults(data);
      setPage(p);
    } catch (e) {
      setError(e?.toString() || "Search failed");
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setQuery(""); setSeverity(""); setMinCvss(""); setYear("");
    setResults(null); setError(null); setPage(1);
  };

  return (
    <Box sx={{ p: 3, pt: 10 }}>
      <Typography variant="h4" sx={{ fontWeight: 700, mb: 0.5 }}>CVE Search</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Search {stats?.total_cves?.toLocaleString() || 0} CVEs from NVD database
      </Typography>

      {/* Search Bar */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} sm={5}>
              <TextField fullWidth size="small" placeholder="Search CVE ID, description..."
                value={query} onChange={e => setQuery(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleSearch(1)}
                InputProps={{ startAdornment: <Search sx={{ mr: 1, color: "#64748b" }} /> }}
                sx={{ "& .MuiOutlinedInput-root": { bgcolor: "#0f172a" } }}
              />
            </Grid>
            <Grid item xs={6} sm={2}>
              <FormControl fullWidth size="small">
                <InputLabel>Severity</InputLabel>
                <Select value={severity} label="Severity" onChange={e => setSeverity(e.target.value)}>
                  {SEVERITIES.map(s => (
                    <MenuItem key={s} value={s}>
                      {s ? <Chip label={s} size="small" sx={{ bgcolor: `${SEV_COLORS[s]}20`, color: SEV_COLORS[s] }} /> : "All"}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={6} sm={2}>
              <TextField fullWidth size="small" label="Min CVSS" type="number"
                inputProps={{ min: 0, max: 10, step: 0.1 }}
                value={minCvss} onChange={e => setMinCvss(e.target.value)}
              />
            </Grid>
            <Grid item xs={6} sm={1}>
              <TextField fullWidth size="small" label="Year" type="number"
                inputProps={{ min: 1999, max: 2025 }}
                value={year} onChange={e => setYear(e.target.value)}
              />
            </Grid>
            <Grid item xs={6} sm={2} sx={{ display: "flex", gap: 1 }}>
              <Button fullWidth variant="contained" onClick={() => handleSearch(1)}
                disabled={loading} startIcon={loading ? <CircularProgress size={14} /> : <FilterList />}>
                Search
              </Button>
              <Button variant="outlined" onClick={handleClear}
                sx={{ borderColor: "#334155", color: "#94a3b8", minWidth: 40, px: 1 }}>
                <Clear fontSize="small" />
              </Button>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Results */}
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {results && (
        <Box>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Found <strong style={{ color: "#3b82f6" }}>{results.total?.toLocaleString()}</strong> CVEs
            {query && ` for "${query}"`}
            {" "}• Page {results.page} of {results.total_pages}
          </Typography>

          {results.items?.map(cve => <CVECard key={cve.id} cve={cve} />)}

          {results.total_pages > 1 && (
            <Box sx={{ display: "flex", justifyContent: "center", mt: 3 }}>
              <Pagination count={results.total_pages} page={page}
                onChange={(_, p) => handleSearch(p)} color="primary"
                sx={{ "& .MuiPaginationItem-root": { color: "#94a3b8" } }}
              />
            </Box>
          )}
        </Box>
      )}

      {!results && !loading && (
        <Box sx={{ textAlign: "center", py: 8, color: "#334155" }}>
          <Search sx={{ fontSize: 64, mb: 2 }} />
          <Typography variant="h6" color="text.secondary">Enter a search query or apply filters</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Try: "log4j", "apache", "CVE-2021", "buffer overflow"
          </Typography>
        </Box>
      )}
    </Box>
  );
}
