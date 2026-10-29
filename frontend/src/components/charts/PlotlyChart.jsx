import React, { useEffect, useRef } from "react";
import { Box, CircularProgress, Typography, Alert } from "@mui/material";

export default function PlotlyChart({
    chartData,
    height = 400,
    loading = false
}) {
    const ref = useRef(null);

    useEffect(() => {
        if (!ref.current || loading) return;

        // Handle empty or error chart data
        if (!chartData) return;
        if (chartData.error) return;

        // Check if chart has actual data traces
        const traces = chartData.data || chartData.traces || [];
        if (!Array.isArray(traces) || traces.length === 0) {
            return;
        }

        // Check if any trace has data
        const hasData = traces.some(trace => {
            const x = trace.x || [];
            const y = trace.y || [];
            return x.length > 0 && y.length > 0;
        });

        if (!hasData) {
            return;
        }

        import("plotly.js-dist-min").then((Plotly) => {
            if (!ref.current) return;

            const layout = {
                ...(chartData.layout || {}),
                paper_bgcolor: "transparent",
                plot_bgcolor: "#0f172a",
                font: {
                    color: "#94a3b8",
                    family: "Inter, sans-serif",
                    size: 11
                },
                xaxis: {
                    ...(chartData.layout?.xaxis || {}),
                    gridcolor: "#1e293b",
                    linecolor: "#334155",
                    tickfont: { color: "#64748b" }
                },
                yaxis: {
                    ...(chartData.layout?.yaxis || {}),
                    gridcolor: "#1e293b",
                    linecolor: "#334155",
                    tickfont: { color: "#64748b" }
                },
                legend: {
                    ...(chartData.layout?.legend || {}),
                    bgcolor: "rgba(15,23,42,0.8)",
                    bordercolor: "#334155",
                    borderwidth: 1,
                    font: { color: "#94a3b8" }
                },
                height: height,
                margin: { t: 50, b: 60, l: 60, r: 30 },
                hoverlabel: {
                    bgcolor: "#1e293b",
                    bordercolor: "#334155",
                    font: { color: "#f1f5f9" }
                }
            };

            const config = {
                responsive: true,
                displayModeBar: true,
                modeBarButtonsToRemove: [
                    "lasso2d", "select2d", "toImage"
                ],
                displaylogo: false
            };

            Plotly.react(
                ref.current,
                traces,
                layout,
                config
            );
        }).catch(err => {
            console.error("Plotly error:", err);
        });

        return () => {
            import("plotly.js-dist-min").then((Plotly) => {
                if (ref.current) Plotly.purge(ref.current);
            });
        };
    }, [chartData, loading, height]);

    if (loading) {
        return (
            <Box sx={{
                height,
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                gap: 2
            }}>
                <CircularProgress size={40} />
                <Typography variant="body2" color="text.secondary">
                    Loading chart...
                </Typography>
            </Box>
        );
    }

    if (!chartData) {
        return (
            <Box sx={{
                height,
                display: "flex",
                alignItems: "center",
                justifyContent: "center"
            }}>
                <Typography color="text.secondary">
                    No chart data available
                </Typography>
            </Box>
        );
    }

    if (chartData.error) {
        return (
            <Alert severity="warning" sx={{ m: 1 }}>
                Chart error: {chartData.error}
            </Alert>
        );
    }

    const traces = chartData.data || chartData.traces || [];
    const hasData = traces.some(t =>
        (t.x || []).length > 0 && (t.y || []).length > 0
    );

    if (!hasData) {
        return (
            <Box sx={{
                height,
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                gap: 1,
                bgcolor: "#0f172a",
                borderRadius: 2,
                border: "1px dashed #334155"
            }}>
                <Typography color="text.secondary" variant="body2">
                    📊 No data to display
                </Typography>
                <Typography
                    color="text.secondary"
                    variant="caption"
                >
                    Collect CVE data first or check API connection
                </Typography>
            </Box>
        );
    }

    return (
        <div
            ref={ref}
            style={{ width: "100%", minHeight: height }}
        />
    );
}
