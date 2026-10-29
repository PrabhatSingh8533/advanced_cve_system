import React, { useState } from "react";
import {
  Box, Typography, Card, CardContent, TextField,
  Button, Grid, Chip, CircularProgress,
  Alert, LinearProgress, Divider, Tab, Tabs
} from "@mui/material";
import { Psychology, Speed, Send } from "@mui/icons-material";
import { bertApi, severityApi } from "../services/api";
import { toast } from "react-toastify";
import { getSeverityColor } from "../theme";
import axios from "axios";

const BASE_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

const SAMPLE_TEXTS = [
  "Apache Log4j2 allows remote attackers to execute arbitrary code via JNDI injection in log messages.",
  "SQL injection vulnerability in the login form allows attackers to bypass authentication via crafted username parameter.",
  "Cross-site scripting (XSS) vulnerability via the search parameter allows injection of arbitrary JavaScript.",
  "Buffer overflow in image parsing library allows remote code execution via specially crafted PNG file.",
  "Denial of service via specially crafted HTTP request causes null pointer dereference and application crash.",
];

export default function AIPrediction() {
  const [text, setText] = useState("");
  const [tab, setTab] = useState(0);
  const [exploitResult, setExploitResult] = useState(null);
  const [severityResult, setSeverityResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handlePredict = async () => {
    if (!text.trim() || text.length < 20) {
      toast.warning("Please enter a longer CVE description (min 20 chars)");
      return;
    }
    setLoading(true);
    setError(null);
    setExploitResult(null);
    setSeverityResult(null);

    try {
      // Exploit type prediction
      try {
        const eResp = await axios.post(
          `${BASE_URL}/api/bert/predict-real`,
          null, { params: { text } }
        );
        setExploitResult(eResp.data?.prediction || eResp.data);
      } catch (e) {
        setExploitResult({ error: e.response?.data?.detail || e.message });
      }

      // Severity prediction
      try {
        const sResp = await axios.post(
          `${BASE_URL}/api/severity/predict`,
          { text, method: "ensemble" }
        );
        setSeverityResult(sResp.data?.prediction || sResp.data);
      } catch (e) {
        setSeverityResult({ error: e.response?.data?.detail || e.message });
      }

    } catch (e) {
      setError(e?.toString() || "Prediction failed");
    } finally {
      setLoading(false);
    }
  };

  const sevColor = getSeverityColor(severityResult?.severity);

  return (
    <Box sx={{ p: 3, pt: 10 }}>
      <Typography variant="h4" sx={{ fontWeight: 700, mb: 0.5 }}>AI Prediction</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Predict exploit type (BERT) and CVSS severity from CVE description
      </Typography>

      <Grid container spacing={3}>
        {/* Input Panel */}
        <Grid item xs={12} md={6}>
          <Card sx={{ height: "100%" }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>📝 CVE Description Input</Typography>

              <TextField fullWidth multiline rows={7}
                placeholder="Paste a CVE description here..."
                value={text} onChange={e => setText(e.target.value)}
                sx={{ mb: 2, "& .MuiOutlinedInput-root": { bgcolor: "#0f172a", fontSize: "0.85rem" } }}
              />

              <Button fullWidth variant="contained" size="large"
                onClick={handlePredict} disabled={loading || text.length < 20}
                startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <Send />}
                sx={{ mb: 2, py: 1.5 }}>
                {loading ? "Analyzing..." : "Predict with AI"}
              </Button>

              <Divider sx={{ my: 2, borderColor: "#334155" }} />

              <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: "block" }}>
                💡 Try a sample:
              </Typography>
              {SAMPLE_TEXTS.map((t, i) => (
                <Chip key={i} label={`Sample ${i + 1}`} size="small" clickable
                  onClick={() => setText(t)}
                  sx={{ mr: 0.5, mb: 0.5, bgcolor: "#1e293b", color: "#94a3b8",
                    "&:hover": { bgcolor: "#3b82f620", color: "#3b82f6" } }}
                />
              ))}
            </CardContent>
          </Card>
        </Grid>

        {/* Results Panel */}
        <Grid item xs={12} md={6}>
          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

          {/* Exploit Type Result */}
          {exploitResult && (
            <Card sx={{ mb: 2, border: "1px solid #3b82f640" }}>
              <CardContent>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                  <Psychology sx={{ color: "#3b82f6" }} />
                  <Typography variant="h6">Exploit Type (BERT)</Typography>
                </Box>

                {exploitResult.error ? (
                  <Alert severity="warning" sx={{ fontSize: "0.8rem" }}>
                    {exploitResult.error}
                    {exploitResult.error.includes("Train") &&
                      " → POST /api/bert/train-real to train first"}
                  </Alert>
                ) : (
                  <>
                    <Box sx={{ bgcolor: "#0f172a", borderRadius: 2, p: 2, mb: 2, textAlign: "center" }}>
                      <Typography variant="h5" sx={{ color: "#3b82f6", fontWeight: 700 }}>
                        {exploitResult.predicted_label || "Unknown"}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Confidence: {((exploitResult.confidence || 0) * 100).toFixed(1)}%
                      </Typography>
                    </Box>

                    {exploitResult.all_probabilities && (
                      <Box>
                        <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: "block" }}>
                          All class probabilities:
                        </Typography>
                        {Object.entries(exploitResult.all_probabilities)
                          .sort((a, b) => b[1] - a[1])
                          .slice(0, 6)
                          .map(([label, prob]) => (
                            <Box key={label} sx={{ mb: 0.8 }}>
                              <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.2 }}>
                                <Typography variant="caption" sx={{ color: "#cbd5e1", fontSize: "0.7rem" }}>{label}</Typography>
                                <Typography variant="caption" sx={{ color: "#64748b" }}>
                                  {(prob * 100).toFixed(1)}%
                                </Typography>
                              </Box>
                              <LinearProgress variant="determinate" value={prob * 100}
                                sx={{ height: 4, borderRadius: 2, bgcolor: "#1e293b",
                                  "& .MuiLinearProgress-bar": {
                                    bgcolor: label === exploitResult.predicted_label ? "#3b82f6" : "#334155"
                                  }
                                }}
                              />
                            </Box>
                          ))}
                      </Box>
                    )}
                  </>
                )}
              </CardContent>
            </Card>
          )}

          {/* Severity Result */}
          {severityResult && (
            <Card sx={{ border: `1px solid ${sevColor}40` }}>
              <CardContent>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                  <Speed sx={{ color: sevColor }} />
                  <Typography variant="h6">Severity Prediction</Typography>
                </Box>

                {severityResult.error ? (
                  <Alert severity="warning" sx={{ fontSize: "0.8rem" }}>
                    {severityResult.error}
                  </Alert>
                ) : (
                  <Grid container spacing={2}>
                    <Grid item xs={6}>
                      <Box sx={{ bgcolor: "#0f172a", borderRadius: 2, p: 2, textAlign: "center",
                        border: `1px solid ${sevColor}30` }}>
                        <Typography variant="h3" sx={{ color: sevColor, fontWeight: 700 }}>
                          {severityResult.cvss_score ?? "—"}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">CVSS Score</Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={6}>
                      <Box sx={{ bgcolor: "#0f172a", borderRadius: 2, p: 2, textAlign: "center",
                        border: `1px solid ${sevColor}30` }}>
                        <Typography variant="h5" sx={{ color: sevColor, fontWeight: 700 }}>
                          {severityResult.severity || "—"}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {severityResult.method || "ensemble"}
                        </Typography>
                      </Box>
                    </Grid>
                    {severityResult.components && (
                      <>
                        <Grid item xs={6}>
                          <Box sx={{ bgcolor: "#1e293b", borderRadius: 1, p: 1.5, textAlign: "center" }}>
                            <Typography variant="body1" sx={{ color: "#8b5cf6", fontWeight: 600 }}>
                              {severityResult.components.classical ?? "—"}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">Classical ML</Typography>
                          </Box>
                        </Grid>
                        <Grid item xs={6}>
                          <Box sx={{ bgcolor: "#1e293b", borderRadius: 1, p: 1.5, textAlign: "center" }}>
                            <Typography variant="body1" sx={{ color: "#06b6d4", fontWeight: 600 }}>
                              {severityResult.components.transformer ?? "—"}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">Transformer</Typography>
                          </Box>
                        </Grid>
                      </>
                    )}
                  </Grid>
                )}
              </CardContent>
            </Card>
          )}

          {!exploitResult && !severityResult && !loading && (
            <Box sx={{ textAlign: "center", py: 8, color: "#334155" }}>
              <Psychology sx={{ fontSize: 64, mb: 2 }} />
              <Typography color="text.secondary">
                Enter a CVE description and click "Predict with AI"
              </Typography>
            </Box>
          )}
        </Grid>
      </Grid>
    </Box>
  );
}
