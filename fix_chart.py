import re

with open("/app/app/services/analytics/charts.py", "r") as f:
    content = f.read()

# Find and replace forecast_chart method
new_method = """
    def forecast_chart(
        self,
        historical_dates: list,
        historical_values: list,
        forecast_dates: list,
        forecast_values: list,
        lower_bound: list,
        upper_bound: list,
        method: str = "ARIMA"
    ) -> dict:
        try:
            # Force convert everything to pure Python types
            h_d = [str(x) for x in (historical_dates or [])]
            h_v = [float(x) if not (isinstance(x, float) and (x != x or x == float("inf") or x == float("-inf"))) else 0.0 for x in (historical_values or [])]
            f_d = [str(x) for x in (forecast_dates or [])]
            f_v = [float(x) if not (isinstance(x, float) and (x != x or x == float("inf") or x == float("-inf"))) else 0.0 for x in (forecast_values or [])]
            lo  = [float(x) if not (isinstance(x, float) and (x != x or x == float("inf") or x == float("-inf"))) else 0.0 for x in (lower_bound or [])]
            hi  = [float(x) if not (isinstance(x, float) and (x != x or x == float("inf") or x == float("-inf"))) else 0.0 for x in (upper_bound or [])]

            if not h_d or not h_v:
                return {"error": "No historical data"}
            if not f_d or not f_v:
                return {"error": "No forecast data"}

            import plotly.graph_objects as go
            fig = go.Figure()

            fig.add_trace(go.Scatter(
                x=h_d, y=h_v,
                mode="lines",
                name="Historical (NVD Real Data)",
                line=dict(color="#3b82f6", width=2)
            ))

            if lo and hi and len(lo) == len(f_d) == len(hi):
                ci_x = [str(v) for v in f_d] + [str(v) for v in reversed(f_d)]
                ci_y = [float(v) for v in hi] + [float(v) for v in reversed(lo)]
                fig.add_trace(go.Scatter(
                    x=ci_x, y=ci_y,
                    fill="toself",
                    fillcolor="rgba(6,182,212,0.15)",
                    line=dict(color="rgba(0,0,0,0)"),
                    name="95% Confidence Interval",
                    hoverinfo="skip"
                ))

            fig.add_trace(go.Scatter(
                x=f_d, y=f_v,
                mode="lines+markers",
                name=f"Forecast ({method})",
                line=dict(color="#06b6d4", width=2.5, dash="dash"),
                marker=dict(size=6)
            ))

            if h_d:
                fig.add_vline(
                    x=str(h_d[-1]),
                    line_dash="dot", line_color="#64748b",
                    annotation_text="Forecast →",
                    annotation_position="top right"
                )

            fig.update_layout(
                title=f"12-Month CVE Count Forecast ({method})",
                title_x=0.5, height=500,
                plot_bgcolor="white", paper_bgcolor="white",
                xaxis_title="Month", yaxis_title="CVE Count",
                hovermode="x unified"
            )

            import json
            return json.loads(fig.to_json())

        except Exception as e:
            import traceback
            print(f"FORECAST CHART ERROR: {e}")
            traceback.print_exc()
            return {"error": str(e)}
"""

# Find the method and replace it
pattern = r"    def forecast_chart\(.*?(?=\n    def |\nclass |\Z)"
replacement = new_method.strip()

new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)

if new_content == content:
    print("WARNING: Pattern not found! Writing append version.")
    # Append fix at end of class
    new_content = content.replace(
        "    def _simple_forecast_chart",
        new_method + "\n    def _simple_forecast_chart"
    )

with open("/app/app/services/analytics/charts.py", "w") as f:
    f.write(new_content)

print("Chart fix applied!")

# Quick test
import sys
sys.path.insert(0, "/app")
try:
    from app.services.analytics.charts import CVEChartGenerator
    gen = CVEChartGenerator()
    result = gen.forecast_chart(
        historical_dates=["2024-01", "2024-02", "2024-03"],
        historical_values=[100.0, 110.0, 120.0],
        forecast_dates=["2024-04", "2024-05"],
        forecast_values=[125.0, 130.0],
        lower_bound=[115.0, 120.0],
        upper_bound=[135.0, 140.0],
        method="ARIMA"
    )
    if result.get("error"):
        print(f"TEST FAILED: {result["error"]}")
    else:
        traces = len(result.get("data", []))
        print(f"TEST PASSED: {traces} traces in chart")
except Exception as e:
    print(f"TEST ERROR: {e}")
    import traceback
    traceback.print_exc()
