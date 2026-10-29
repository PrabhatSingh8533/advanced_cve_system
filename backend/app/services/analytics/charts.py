"""CVE Charts - Fixed: no add_vline, proper type handling."""

import json
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from loguru import logger


def _sl(values) -> list:
    """Any iterable -> list of plain str."""
    return [str(v) for v in list(values or [])]


def _fl(values) -> list:
    """Any iterable -> list of plain float."""
    result = []
    for v in list(values or []):
        try:
            f = float(v)
            result.append(0.0 if (f != f or abs(f) == float("inf")) else f)
        except Exception:
            result.append(0.0)
    return result


def _json(fig) -> dict:
    try:
        return json.loads(fig.to_json())
    except Exception as e:
        return {"error": str(e)}


COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
    "primary":  "#3b82f6",
    "secondary":"#8b5cf6",
    "forecast": "#06b6d4",
}


class CVEChartGenerator:
    """All Plotly charts - type-safe, no add_vline."""

    def _sl(self, v): return _sl(v)
    def _fl(self, v): return _fl(v)
    def _safe_json(self, fig): return _json(fig)

    # ── Forecast ───────────────────────────────────────────
    def forecast_chart(
        self,
        historical_dates,
        historical_values,
        forecast_dates,
        forecast_values,
        lower_bound,
        upper_bound,
        method="ARIMA"
    ) -> dict:
        """
        Forecast chart.
        NO add_vline (breaks on string x-axis).
        Uses a scatter line as divider instead.
        """
        try:
            # ── Force plain Python types ──
            h_d = [str(x) for x in list(historical_dates or [])]
            h_v = [float(x) if not (
                       float(x) != float(x) or
                       abs(float(x)) == float("inf")
                   ) else 0.0
                   for x in list(historical_values or [])]

            f_d = [str(x) for x in list(forecast_dates or [])]
            f_v = [float(x) if not (
                       float(x) != float(x) or
                       abs(float(x)) == float("inf")
                   ) else 0.0
                   for x in list(forecast_values or [])]

            lo  = [float(x) if not (
                       float(x) != float(x) or
                       abs(float(x)) == float("inf")
                   ) else 0.0
                   for x in list(lower_bound or [])]

            hi  = [float(x) if not (
                       float(x) != float(x) or
                       abs(float(x)) == float("inf")
                   ) else 0.0
                   for x in list(upper_bound or [])]

            if not h_d or not h_v:
                return {"error": "No historical data"}
            if not f_d or not f_v:
                return {"error": "No forecast data"}

            logger.info(
                f"Forecast chart: hist={len(h_d)} fc={len(f_d)}"
            )

            fig = go.Figure()

            # 1. Historical line
            fig.add_trace(go.Scatter(
                x=h_d, y=h_v,
                mode="lines",
                name="Historical (NVD Real Data)",
                line=dict(color=COLORS["primary"], width=2)
            ))

            # 2. CI band - ALL lists verified str/float above
            if lo and hi and len(lo) == len(f_d) == len(hi):
                # Build manually - no slice operations
                ci_x_fwd = [str(v) for v in f_d]
                ci_x_rev = [str(f_d[i]) for i in range(len(f_d)-1, -1, -1)]
                ci_y_fwd = [float(v) for v in hi]
                ci_y_rev = [float(lo[i]) for i in range(len(lo)-1, -1, -1)]

                ci_x = ci_x_fwd + ci_x_rev
                ci_y = ci_y_fwd + ci_y_rev

                fig.add_trace(go.Scatter(
                    x=ci_x, y=ci_y,
                    fill="toself",
                    fillcolor="rgba(6,182,212,0.15)",
                    line=dict(color="rgba(0,0,0,0)"),
                    name="95% Confidence Interval",
                    hoverinfo="skip",
                    showlegend=True
                ))

            # 3. Forecast line
            fig.add_trace(go.Scatter(
                x=f_d, y=f_v,
                mode="lines+markers",
                name=f"Forecast ({method})",
                line=dict(
                    color=COLORS["forecast"],
                    width=2.5, dash="dash"
                ),
                marker=dict(size=6)
            ))

            # 4. Divider as vertical line TRACE (not add_vline!)
            if h_d and f_d:
                max_y = max(
                    max(h_v) if h_v else 0,
                    max(f_v) if f_v else 0
                ) * 1.1 if (h_v or f_v) else 1000.0

                # Use last historical date as x for both points
                div_x = str(h_d[-1])
                fig.add_trace(go.Scatter(
                    x=[div_x, div_x],
                    y=[0.0, float(max_y)],
                    mode="lines",
                    line=dict(color="#64748b", width=1.5, dash="dot"),
                    name="Forecast Start",
                    showlegend=False,
                    hoverinfo="skip"
                ))

                # Add annotation text instead of add_vline annotation
                fig.add_annotation(
                    x=div_x,
                    y=float(max_y),
                    text="◄ Historical | Forecast ►",
                    showarrow=False,
                    yref="y",
                    xref="x",
                    font=dict(color="#64748b", size=11),
                    bgcolor="rgba(15,23,42,0.8)",
                    bordercolor="#334155",
                    borderwidth=1,
                    xanchor="center"
                )

            fig.update_layout(
                title=f"12-Month CVE Count Forecast ({method})",
                title_x=0.5,
                height=500,
                plot_bgcolor="white",
                paper_bgcolor="white",
                xaxis_title="Month",
                yaxis_title="CVE Count",
                hovermode="x unified",
                legend=dict(
                    yanchor="top", y=0.99,
                    xanchor="left", x=0.01
                )
            )

            result = _json(fig)
            logger.info(
                f"Forecast chart built: "
                f"{len(result.get('data',[]))} traces"
            )
            return result

        except Exception as e:
            logger.error(f"Forecast chart error: {e}", exc_info=True)
            return {"error": str(e)}

    # ── Monthly Trend ───────────────────────────────────────
    def monthly_trend_chart(self, df: pd.DataFrame) -> dict:
        try:
            dates = _sl(df["date"].dt.strftime("%Y-%m").tolist())
            vals  = _fl(df["total_cves"].tolist())

            fig = make_subplots(
                rows=2, cols=1,
                subplot_titles=(
                    "Monthly CVE Count",
                    "Year-over-Year Growth (%)"
                ),
                vertical_spacing=0.15,
                row_heights=[0.7, 0.3]
            )

            fig.add_trace(go.Scatter(
                x=dates, y=vals,
                mode="lines", name="Monthly CVEs",
                line=dict(color=COLORS["primary"], width=1.5),
                opacity=0.7
            ), row=1, col=1)

            if "rolling_mean_12m" in df.columns:
                rolling = _fl(df["rolling_mean_12m"].tolist())
                fig.add_trace(go.Scatter(
                    x=dates, y=rolling,
                    mode="lines", name="12-Month Avg",
                    line=dict(color=COLORS["secondary"], width=2.5)
                ), row=1, col=1)

            yearly = (
                df.groupby("year")["total_cves"]
                .sum().reset_index()
            )
            yearly["yoy"] = (
                yearly["total_cves"].pct_change() * 100
            ).fillna(0).round(1)

            yoy_vals = _fl(yearly["yoy"].tolist())
            fig.add_trace(go.Bar(
                x=_sl(yearly["year"].tolist()),
                y=yoy_vals,
                name="YoY Growth %",
                marker_color=[
                    COLORS["HIGH"] if v >= 0 else COLORS["LOW"]
                    for v in yoy_vals
                ]
            ), row=2, col=1)

            fig.update_layout(
                height=600, showlegend=True,
                plot_bgcolor="white", paper_bgcolor="white",
                title_text="CVE Temporal Analysis", title_x=0.5
            )
            return _json(fig)
        except Exception as e:
            logger.error(f"Monthly chart: {e}")
            return {"error": str(e)}

    # ── Severity Trend ──────────────────────────────────────
    def severity_trend_chart(self, df: pd.DataFrame) -> dict:
        try:
            sev_map = {
                "sev_critical": ("CRITICAL", COLORS["CRITICAL"]),
                "sev_high":     ("HIGH",     COLORS["HIGH"]),
                "sev_medium":   ("MEDIUM",   COLORS["MEDIUM"]),
                "sev_low":      ("LOW",      COLORS["LOW"]),
            }
            available = {
                k: v for k, v in sev_map.items() if k in df.columns
            }
            if not available:
                return {"error": "No severity columns"}

            dates = _sl(df["date"].dt.strftime("%Y-%m").tolist())
            fig   = go.Figure()

            for col, (label, color) in available.items():
                fig.add_trace(go.Scatter(
                    x=dates, y=_fl(df[col].tolist()),
                    mode="lines", name=label,
                    line=dict(color=color, width=0.5),
                    fill="tonexty", stackgroup="one"
                ))

            fig.update_layout(
                title="CVE Severity Distribution Over Time",
                title_x=0.5, height=450,
                plot_bgcolor="white", paper_bgcolor="white"
            )
            return _json(fig)
        except Exception as e:
            return {"error": str(e)}

    # ── RCE Trend ───────────────────────────────────────────
    def rce_trend_chart(self, df: pd.DataFrame) -> dict:
        try:
            dates  = _sl(df["date"].dt.strftime("%Y-%m").tolist())
            counts = _fl(df["rce_count"].tolist())
            pcts   = _fl(df["rce_percentage"].tolist())

            fig = make_subplots(specs=[[{"secondary_y": True}]])
            fig.add_trace(go.Bar(
                x=dates, y=counts,
                name="RCE Count",
                marker_color=COLORS["CRITICAL"], opacity=0.7
            ), secondary_y=False)
            fig.add_trace(go.Scatter(
                x=dates, y=pcts,
                mode="lines", name="RCE %",
                line=dict(color=COLORS["secondary"], width=2)
            ), secondary_y=True)

            fig.update_layout(
                title="RCE Trend Analysis", title_x=0.5,
                height=450, plot_bgcolor="white",
                paper_bgcolor="white"
            )
            fig.update_yaxes(title_text="RCE Count", secondary_y=False)
            fig.update_yaxes(
                title_text="RCE %", secondary_y=True, range=[0, 50]
            )
            return _json(fig)
        except Exception as e:
            return {"error": str(e)}

    # ── OS Distribution ─────────────────────────────────────
    def os_distribution_chart(self, df: pd.DataFrame) -> dict:
        try:
            colors = px.colors.qualitative.Set2
            fig    = go.Figure()
            for i, os_name in enumerate(df["os"].unique()):
                d = df[df["os"] == os_name]
                fig.add_trace(go.Bar(
                    x=_sl(d["year"].tolist()),
                    y=_fl(d["count"].tolist()),
                    name=os_name,
                    marker_color=colors[i % len(colors)]
                ))
            fig.update_layout(
                title="CVE by OS/Platform", title_x=0.5,
                barmode="group", height=500,
                plot_bgcolor="white", paper_bgcolor="white"
            )
            return _json(fig)
        except Exception as e:
            return {"error": str(e)}

    # ── Exploit Heatmap ─────────────────────────────────────
    def exploit_heatmap(self, df: pd.DataFrame) -> dict:
        """
        Heatmap - always uses synthetic data because
        real DB monthly data doesn't have exploit_ columns.
        """
        try:
            # Always use synthetic data for heatmap
            # (real DB doesn't store monthly exploit breakdown)
            from app.services.analytics.synthetic_data import (
                CVETimeSeriesGenerator
            )
            gen      = CVETimeSeriesGenerator()
            syn_df   = gen.generate_monthly_counts()

            cols = [
                c for c in syn_df.columns
                if c.startswith("exploit_")
            ]

            if not cols:
                return {"error": "Cannot generate exploit data"}

            yearly = syn_df.groupby("year")[cols].sum()
            clean_cols = [
                c.replace("exploit_", "")
                 .replace("_", " ").title()
                for c in yearly.columns
            ]
            yearly.columns = clean_cols

            z        = [_fl(row.tolist()) for row in yearly.values]
            y_labels = _sl(yearly.index.tolist())

            fig = go.Figure(data=go.Heatmap(
                z=z,
                x=clean_cols,
                y=y_labels,
                colorscale="YlOrRd",
                text=[[str(int(v)) for v in row] for row in z],
                texttemplate="%{text}",
                textfont={"size": 10},
                hoverongaps=False,
                colorbar=dict(title="CVE Count")
            ))

            fig.update_layout(
                title="CVE Exploit Type Distribution by Year",
                title_x=0.5, height=450,
                plot_bgcolor="white", paper_bgcolor="white",
                xaxis_title="Exploit Type",
                yaxis_title="Year",
                xaxis_tickangle=-30
            )
            return _json(fig)

        except Exception as e:
            logger.error(f"Heatmap error: {e}", exc_info=True)
            return {"error": str(e)}