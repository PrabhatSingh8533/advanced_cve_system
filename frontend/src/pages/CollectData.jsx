import React, { useState, useEffect, useRef } from "react";
import {
  Box, Typography, Grid, Card, CardContent,
  Button, Chip, LinearProgress, Alert,
  CircularProgress, Select, MenuItem,
  FormControl, InputLabel, Table,
  TableBody, TableCell, TableHead,
  TableRow, Divider, Tooltip
} from "@mui/material";
import {
  Download, CheckCircle, Error, PlayArrow,
  Refresh, Storage, Warning, History,
  TrendingUp, SkipNext, AddCircle
} from "@mui/icons-material";
import { toast } from "react-toastify";
import axios from "axios";

const BASE_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

const SEV_COLORS = {
  CRITICAL: "#dc2626",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#22c55e",
};

// ── Small stat box ─────────────────────────────────────
function StatBox({ label, value, color, icon: Icon }) {
  return (
    <Box sx={{
      bgcolor: "#0f172a", borderRadius: 2, p: 1.5,
      textAlign: "center", border: `1px solid ${color}30`,
      flex: 1
    }}>
      {Icon && <Icon sx={{ color, fontSize: 20, mb: 0.5 }} />}
      <Typography variant="h6" sx={{ color, fontWeight: 700, lineHeight: 1 }}>
        {(value || 0).toLocaleString()}
      </Typography>
      <Typography variant="caption" sx={{ color: "#64748b", fontSize: "0.65rem" }}>
        {label}
      </Typography>
    </Box>
  );
}

export default function CollectData() {
  const [status, setStatus]         = useState(null);
  const [loading, setLoading]       = useState(true);
  const [collecting, setCollecting] = useState(false);
  const [selectedYear, setSelectedYear] = useState(new Date().getFullYear());
  const [recentDays, setRecentDays] = useState(30);
  const [history, setHistory]       = useState([]);   // collection history log
  const pollRef = useRef(null);

  const currentYear = new Date().getFullYear();
  const years = Array.from(
    { length: currentYear - 1999 + 1 },
    (_, i) => currentYear - i
  );

  // ── Fetch status ───────────────────────────────────
  const fetchStatus = async () => {
    try {
      const resp = await axios.get(`${BASE_URL}/api/collect/status`, {
        headers: { "ngrok-skip-browser-warning": "69420" },
      });
      const data = resp.data;
      setStatus(data);

      const running = data?.collection?.is_running;
      setCollecting(running);

      if (!running && pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;

        const last = data?.collection?.last_result;
        if (last) {
          // Add to history log
          setHistory(prev => [{
            timestamp: new Date().toLocaleTimeString(),
            task:      last.task || "unknown",
            fetched:   last.fetched || 0,
            saved:     last.saved   || 0,
            skipped:   last.skipped || 0,
            errors:    last.errors  || 0,
            total_db:  last.total_in_db || 0,
          }, ...prev].slice(0, 10)); // keep last 10

          if (last.saved > 0) {
            toast.success(
              `✅ Done! ${last.saved.toLocaleString()} new CVEs added`
            );
          } else {
            toast.info(
              `ℹ️ Done! All ${last.skipped?.toLocaleString()} CVEs already existed`
            );
          }
        }
      }
    } catch (e) {
      console.error("Status error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  const startPolling = () => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(fetchStatus, 4000);
  };

  const handleCollectRecent = async () => {
    try {
      setCollecting(true);
      await axios.post(
        `${BASE_URL}/api/collect/recent?days=${recentDays}`,
        {},
        { headers: { "ngrok-skip-browser-warning": "69420" } }
      );
      toast.info(`🚀 Collecting last ${recentDays} days from NVD...`);
      startPolling();
    } catch (e) {
      toast.error(e.response?.data?.detail || e.message);
      setCollecting(false);
    }
  };

  const handleCollectYear = async () => {
    try {
      setCollecting(true);
      await axios.post(
        `${BASE_URL}/api/collect/year/${selectedYear}`,
        {},
        { headers: { "ngrok-skip-browser-warning": "69420" } }
      );
      toast.info(`🚀 Collecting year ${selectedYear} from NVD...`);
      startPolling();
    } catch (e) {
      toast.error(e.response?.data?.detail || e.message);
      setCollecting(false);
    }
  };

  const db          = status?.database   || {};
  const collection  = status?.collection || {};
  const progress    = collection?.progress || {};
  const isRunning   = collection?.is_running;
  const lastResult  = collection?.last_result;
  const colError    = collection?.error;

  return (
    <Box sx={{ p: 3, pt: 10 }}>

      {/* ── Header ── */}
      <Box sx={{ display:"flex", alignItems:"center", gap:2, mb:3 }}>
        <Storage sx={{ color:"#3b82f6", fontSize:32 }} />
        <Box sx={{ flexGrow:1 }}>
          <Typography variant="h4" sx={{ fontWeight:700 }}>
            CVE Data Collection
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Fetch real vulnerability data from NVD API • {db.total_cves?.toLocaleString() || 0} CVEs in database
          </Typography>
        </Box>
        <Button startIcon={<Refresh />} onClick={fetchStatus}
          variant="outlined" size="small"
          sx={{ borderColor:"#334155", color:"#94a3b8" }}>
          Refresh
        </Button>
      </Box>

      {/* ── Status Alerts ── */}
      {isRunning && (
        <Alert severity="info"
          icon={<CircularProgress size={18} />}
          sx={{ mb:2, bgcolor:"#1e3a5f", border:"1px solid #3b82f6" }}>
          <strong>Collection running...</strong> Auto-refreshing every 4s.
          {progress.fetched > 0 &&
            ` Fetched: ${progress.fetched?.toLocaleString()} CVEs so far`}
        </Alert>
      )}

      {colError && !isRunning && (
        <Alert severity="error" icon={<Error />} sx={{ mb:2 }}>
          <strong>Error:</strong> {colError}
        </Alert>
      )}

      {lastResult && !isRunning && !colError && (
        <Alert severity="success" icon={<CheckCircle />}
          sx={{ mb:2, bgcolor:"#14532d30", border:"1px solid #22c55e" }}>
          <strong>Last run:</strong>&nbsp;
          Fetched <strong>{lastResult.fetched?.toLocaleString()}</strong> •&nbsp;
          <span style={{color:"#22c55e"}}>
            Added <strong>{lastResult.saved?.toLocaleString()}</strong>
          </span> •&nbsp;
          <span style={{color:"#eab308"}}>
            Skipped <strong>{lastResult.skipped?.toLocaleString()}</strong>
          </span> •&nbsp;
          Total in DB: <strong>{lastResult.total_in_db?.toLocaleString()}</strong>
        </Alert>
      )}

      <Grid container spacing={3}>

        {/* ── LEFT: DB Stats ── */}
        <Grid item xs={12} md={4}>
          <Card sx={{ mb:2 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb:2 }}>
                📊 Database Statistics
              </Typography>

              {loading ? (
                <Box sx={{ display:"flex", justifyContent:"center", p:3 }}>
                  <CircularProgress />
                </Box>
              ) : (
                <>
                  {/* Total */}
                  <Box sx={{
                    bgcolor:"#0f172a", borderRadius:2, p:2, mb:2,
                    border:"1px solid #334155", textAlign:"center"
                  }}>
                    <Typography variant="h3"
                      sx={{ color:"#3b82f6", fontWeight:700 }}>
                      {db.total_cves?.toLocaleString() || 0}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Total CVEs in Database
                    </Typography>
                  </Box>

                  {/* Severity bars */}
                  <Typography variant="subtitle2"
                    sx={{ mb:1, color:"#94a3b8" }}>
                    Severity Breakdown
                  </Typography>
                  {Object.entries(SEV_COLORS).map(([sev, color]) => {
                    const count = db.severity_distribution?.[sev] || 0;
                    const total = db.total_cves || 1;
                    return (
                      <Box key={sev} sx={{ mb:1 }}>
                        <Box sx={{ display:"flex", justifyContent:"space-between", mb:0.3 }}>
                          <Chip label={sev} size="small"
                            sx={{ bgcolor:`${color}20`, color,
                              fontSize:"0.65rem", height:20 }} />
                          <Typography variant="caption"
                            sx={{ color:"#64748b" }}>
                            {count.toLocaleString()}
                            <span style={{ color:"#475569", marginLeft:4 }}>
                              ({((count/total)*100).toFixed(1)}%)
                            </span>
                          </Typography>
                        </Box>
                        <LinearProgress variant="determinate"
                          value={(count/total)*100}
                          sx={{ height:5, borderRadius:3, bgcolor:"#1e293b",
                            "& .MuiLinearProgress-bar":{ bgcolor:color } }} />
                      </Box>
                    );
                  })}

                  {/* Date range */}
                  {db.date_range?.earliest && (
                    <Box sx={{ mt:2, p:1.5, bgcolor:"#0f172a",
                      borderRadius:1, border:"1px solid #334155" }}>
                      <Typography variant="caption"
                        sx={{ color:"#64748b", display:"block" }}>
                        📅 Date Range
                      </Typography>
                      <Typography variant="body2"
                        sx={{ color:"#cbd5e1", fontSize:"0.8rem" }}>
                        {db.date_range.earliest} → {db.date_range.latest}
                      </Typography>
                    </Box>
                  )}

                  {/* Year breakdown */}
                  {db.year_distribution && (
                    <Box sx={{ mt:2 }}>
                      <Typography variant="caption"
                        sx={{ color:"#64748b", display:"block", mb:1 }}>
                        📈 CVEs by Year
                      </Typography>
                      {Object.entries(db.year_distribution)
                        .sort((a,b) => b[0]-a[0])
                        .slice(0, 8)
                        .map(([yr, cnt]) => {
                          const maxVal = Math.max(
                            ...Object.values(db.year_distribution)
                          );
                          return (
                            <Box key={yr} sx={{ mb:0.8 }}>
                              <Box sx={{ display:"flex",
                                justifyContent:"space-between", mb:0.2 }}>
                                <Typography variant="caption"
                                  sx={{ color:"#94a3b8", fontWeight:600 }}>
                                  {yr}
                                </Typography>
                                <Typography variant="caption"
                                  sx={{ color:"#3b82f6" }}>
                                  {Number(cnt).toLocaleString()}
                                </Typography>
                              </Box>
                              <LinearProgress
                                variant="determinate"
                                value={(cnt / maxVal) * 100}
                                sx={{ height:4, borderRadius:2,
                                  bgcolor:"#1e293b",
                                  "& .MuiLinearProgress-bar":{
                                    bgcolor: yr >= currentYear ? "#22c55e"
                                      : yr >= currentYear-1 ? "#3b82f6"
                                      : "#475569"
                                  }
                                }}
                              />
                            </Box>
                          );
                        })}
                    </Box>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* ── RIGHT: Controls + Progress ── */}
        <Grid item xs={12} md={8}>
          <Grid container spacing={2}>

            {/* Collect Recent */}
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Box sx={{ display:"flex", alignItems:"center",
                    gap:1, mb:1 }}>
                    <Download sx={{ color:"#22c55e" }} />
                    <Typography variant="h6">Collect Recent CVEs</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary"
                    sx={{ mb:2 }}>
                    Fetch CVEs published in the last N days. Best for
                    keeping database up-to-date.
                  </Typography>
                  <Box sx={{ display:"flex", gap:2, alignItems:"center" }}>
                    <FormControl size="small" sx={{ minWidth:150 }}>
                      <InputLabel sx={{ color:"#94a3b8" }}>
                        Days Back
                      </InputLabel>
                      <Select value={recentDays} label="Days Back"
                        onChange={e => setRecentDays(e.target.value)}
                        sx={{ color:"#f1f5f9",
                          "& .MuiOutlinedInput-notchedOutline":{
                            borderColor:"#334155" } }}>
                        {[7,14,30,60,90,180,365].map(d => (
                          <MenuItem key={d} value={d}>
                            Last {d} days
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                    <Button variant="contained"
                      startIcon={collecting
                        ? <CircularProgress size={16} color="inherit" />
                        : <PlayArrow />}
                      onClick={handleCollectRecent}
                      disabled={collecting}
                      sx={{ bgcolor:"#22c55e",
                        "&:hover":{ bgcolor:"#16a34a" },
                        "&:disabled":{ bgcolor:"#1e293b" } }}>
                      {collecting ? "Running..." : "Start Collection"}
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* Collect Year */}
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Box sx={{ display:"flex", alignItems:"center",
                    gap:1, mb:1 }}>
                    <Download sx={{ color:"#8b5cf6" }} />
                    <Typography variant="h6">Collect Full Year</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary"
                    sx={{ mb:1 }}>
                    Fetch all CVEs for an entire year from NVD API.
                  </Typography>
                  <Alert severity="warning"
                    sx={{ mb:2, bgcolor:"#1c1200",
                      border:"1px solid #eab308" }}>
                    <Typography variant="caption">
                      ⏱️ Takes 5-20 minutes. Runs in background.
                    </Typography>
                  </Alert>
                  <Box sx={{ display:"flex", gap:2, alignItems:"center" }}>
                    <FormControl size="small" sx={{ minWidth:120 }}>
                      <InputLabel sx={{ color:"#94a3b8" }}>Year</InputLabel>
                      <Select value={selectedYear} label="Year"
                        onChange={e => setSelectedYear(e.target.value)}
                        sx={{ color:"#f1f5f9",
                          "& .MuiOutlinedInput-notchedOutline":{
                            borderColor:"#334155" } }}>
                        {years.map(y => (
                          <MenuItem key={y} value={y}>{y}</MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                    <Button variant="contained"
                      startIcon={collecting
                        ? <CircularProgress size={16} color="inherit" />
                        : <PlayArrow />}
                      onClick={handleCollectYear}
                      disabled={collecting}
                      sx={{ bgcolor:"#8b5cf6",
                        "&:hover":{ bgcolor:"#7c3aed" },
                        "&:disabled":{ bgcolor:"#1e293b" } }}>
                      {collecting ? "Running..." : `Collect ${selectedYear}`}
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* ── Live Progress ── */}
            {(isRunning || progress.fetched > 0) && (
              <Grid item xs={12}>
                <Card sx={{ border:"1px solid #3b82f6" }}>
                  <CardContent>
                    <Box sx={{ display:"flex", alignItems:"center",
                      gap:1, mb:2 }}>
                      {isRunning
                        ? <CircularProgress size={18} sx={{ color:"#3b82f6" }} />
                        : <CheckCircle sx={{ color:"#22c55e" }} />}
                      <Typography variant="h6">
                        {isRunning ? "Live Progress" : "Last Run Summary"}
                      </Typography>
                      {collection.task && (
                        <Chip label={collection.task} size="small"
                          sx={{ bgcolor:"#1e293b", color:"#94a3b8",
                            fontSize:"0.65rem" }} />
                      )}
                    </Box>

                    {/* Stats row */}
                    <Box sx={{ display:"flex", gap:1.5, mb:2, flexWrap:"wrap" }}>
                      <StatBox label="Fetched from NVD"
                        value={progress.fetched} color="#3b82f6"
                        icon={Download} />
                      <StatBox label="New CVEs Added"
                        value={progress.saved} color="#22c55e"
                        icon={AddCircle} />
                      <StatBox label="Already Existed"
                        value={progress.skipped} color="#eab308"
                        icon={SkipNext} />
                      <StatBox label="Total in DB"
                        value={progress.total_in_db} color="#8b5cf6"
                        icon={Storage} />
                    </Box>

                    {/* Added vs Skipped bar */}
                    {progress.fetched > 0 && (
                      <Box sx={{ mb:1 }}>
                        <Box sx={{ display:"flex",
                          justifyContent:"space-between", mb:0.5 }}>
                          <Typography variant="caption"
                            sx={{ color:"#22c55e" }}>
                            New: {((progress.saved/progress.fetched)*100).toFixed(1)}%
                          </Typography>
                          <Typography variant="caption"
                            sx={{ color:"#eab308" }}>
                            Existing: {((progress.skipped/progress.fetched)*100).toFixed(1)}%
                          </Typography>
                        </Box>
                        <Box sx={{ display:"flex", borderRadius:2,
                          overflow:"hidden", height:10 }}>
                          <Box sx={{
                            width:`${(progress.saved/progress.fetched)*100}%`,
                            bgcolor:"#22c55e", transition:"width 0.5s"
                          }} />
                          <Box sx={{
                            width:`${(progress.skipped/progress.fetched)*100}%`,
                            bgcolor:"#eab308"
                          }} />
                        </Box>
                      </Box>
                    )}

                    {isRunning && (
                      <LinearProgress
                        sx={{ mt:1, borderRadius:1, bgcolor:"#1e293b",
                          "& .MuiLinearProgress-bar":{ bgcolor:"#3b82f6" } }}
                      />
                    )}
                  </CardContent>
                </Card>
              </Grid>
            )}

            {/* ── Collection History Log ── */}
            {history.length > 0 && (
              <Grid item xs={12}>
                <Card>
                  <CardContent>
                    <Box sx={{ display:"flex", alignItems:"center",
                      gap:1, mb:2 }}>
                      <History sx={{ color:"#64748b" }} />
                      <Typography variant="h6">
                        Collection History
                      </Typography>
                      <Typography variant="caption"
                        sx={{ color:"#64748b", ml:"auto" }}>
                        This session only
                      </Typography>
                    </Box>

                    <Box sx={{ overflowX:"auto" }}>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            {["Time","Task","Fetched","Added","Skipped","Total DB"].map(h => (
                              <TableCell key={h} sx={{
                                color:"#64748b", fontWeight:700,
                                borderBottom:"1px solid #334155",
                                fontSize:"0.72rem", py:0.8
                              }}>
                                {h}
                              </TableCell>
                            ))}
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {history.map((row, i) => (
                            <TableRow key={i}
                              sx={{ "&:hover":{ bgcolor:"#1e293b" } }}>
                              <TableCell sx={{ color:"#94a3b8",
                                borderBottom:"1px solid #1e293b",
                                fontSize:"0.75rem" }}>
                                {row.timestamp}
                              </TableCell>
                              <TableCell sx={{ borderBottom:"1px solid #1e293b" }}>
                                <Chip label={row.task} size="small"
                                  sx={{ bgcolor:"#1e293b", color:"#94a3b8",
                                    fontSize:"0.65rem" }} />
                              </TableCell>
                              <TableCell sx={{ color:"#3b82f6",
                                borderBottom:"1px solid #1e293b",
                                fontWeight:600, fontSize:"0.8rem" }}>
                                {row.fetched?.toLocaleString()}
                              </TableCell>
                              <TableCell sx={{ color:"#22c55e",
                                borderBottom:"1px solid #1e293b",
                                fontWeight:600, fontSize:"0.8rem" }}>
                                +{row.saved?.toLocaleString()}
                              </TableCell>
                              <TableCell sx={{ color:"#eab308",
                                borderBottom:"1px solid #1e293b",
                                fontSize:"0.8rem" }}>
                                {row.skipped?.toLocaleString()}
                              </TableCell>
                              <TableCell sx={{ color:"#8b5cf6",
                                borderBottom:"1px solid #1e293b",
                                fontWeight:600, fontSize:"0.8rem" }}>
                                {row.total_db?.toLocaleString()}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            )}


          </Grid>
        </Grid>
      </Grid>
    </Box>
  );
}