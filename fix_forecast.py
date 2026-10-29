# Read current file
with open("/app/app/services/analytics/charts.py", "r") as f:
    content = f.read()

# New forecast_chart - completely self-contained type handling
new_method = """    def forecast_chart(
        self,
        historical_dates,
        historical_values,
        forecast_dates,
        forecast_values,
        lower_bound,
        upper_bound,
        method="ARIMA"
    ):
        import json
        import numpy as np
        import plotly.graph_objects as go

        try:
            # Convert EVERYTHING to plain Python lists
            # No numpy arrays, no mixed types
            def to_str_list(x):
                if x is None: return []
                return [str(v) for v in list(x)]

            def to_float_list(x):
                if x is None: return []
                result = []
                for v in list(x):
                    try:
                        f = float(v)
                        result.append(0.0 if (f != f or f == float("inf") or f == float("-inf")) else f)
                    except:
                        result.append(0.0)
                return result

            h_d = to_str_list(historical_dates)
            h_v = to_float_list(historical_values)
            f_d = to_str_list(forecast_dates)
            f_v = to_float_list(forecast_values)
            lo  = to_float_list(lower_bound)
            hi  = to_float_list(upper_bound)

            # Verify
            assert all(type(x) is str for x in h_d), f"h_d bad types: {set(type(x).__name__ for x in h_d)}"
            assert all(type(x) is str for x in f_d), f"f_d bad types: {set(type(x).__name__ for x in f_d)}"
            assert all(type(x) is float for x in h_v), f"h_v bad types: {set(type(x).__name__ for x in h_v)}"
            assert all(type(x) is float for x in f_v), f"f_v bad types: {set(type(x).__name__ for x in f_v)}"
            assert all(type(x) is float for x in lo),  f"lo bad types: {set(type(x).__name__ for x in lo)}"
            assert all(type(x) is float for x in hi),  f"hi bad types: {set(type(x).__name__ for x in hi)}"

            if not h_d or not h_v:
                return {"error": "No historical data"}
            if not f_d or not f_v:
                return {"error": "No forecast data"}

            fig = go.Figure()

            # Historical
            fig.add_trace(go.Scatter(
                x=h_d, y=h_v,
                mode="lines",
                name="Historical (NVD Real Data)",
                line=dict(color="#3b82f6", width=2)
            ))

            # CI Band
            if lo and hi and len(lo) == len(f_d) == len(hi):
                # Build lists manually - no slicing that could return numpy
                f_d_rev = list(reversed(f_d))
                lo_rev  = list(reversed(lo))

                ci_x = [str(v) for v in f_d] + [str(v) for v in f_d_rev]
                ci_y = [float(v) for v in hi] + [float(v) for v in lo_rev]

                fig.add_trace(go.Scatter(
                    x=ci_x, y=ci_y,
                    fill="toself",
                    fillcolor="rgba(6,182,212,0.15)",
                    line=dict(color="rgba(0,0,0,0)"),
                    name="95% Confidence Interval",
                    hoverinfo="skip"
                ))

            # Forecast
            fig.add_trace(go.Scatter(
                x=f_d, y=f_v,
                mode="lines+markers",
                name=f"Forecast ({method})",
                line=dict(color="#06b6d4", width=2.5, dash="dash"),
                marker=dict(size=6)
            ))

            # Divider
            fig.add_vline(
                x=str(h_d[-1]),
                line_dash="dot", line_color="#64748b",
                annotation_text="Forecast ?",
                annotation_position="top right"
            )

            fig.update_layout(
                title=f"12-Month CVE Count Forecast ({method})",
                title_x=0.5, height=500,
                plot_bgcolor="white", paper_bgcolor="white",
                xaxis_title="Month", yaxis_title="CVE Count",
                hovermode="x unified"
            )

            return json.loads(fig.to_json())

        except AssertionError as ae:
            print(f"TYPE ASSERT: {ae}")
            # Fallback: no CI band
            try:
                import plotly.graph_objects as go
                import json
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=[str(v) for v in list(historical_dates or [])],
                    y=[float(v) for v in list(historical_values or [])],
                    mode="lines", name="Historical",
                    line=dict(color="#3b82f6", width=2)
                ))
                fig.add_trace(go.Scatter(
                    x=[str(v) for v in list(forecast_dates or [])],
                    y=[float(v) for v in list(forecast_values or [])],
                    mode="lines+markers",
                    name=f"Forecast ({method})",
                    line=dict(color="#06b6d4", width=2.5, dash="dash")
                ))
                fig.update_layout(
                    title=f"CVE Forecast ({method})",
                    title_x=0.5, height=500,
                    plot_bgcolor="white", paper_bgcolor="white"
                )
                return json.loads(fig.to_json())
            except Exception as e2:
                return {"error": str(e2)}

        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"error": str(e)}
"""

# Find start of forecast_chart method
start_marker = "    def forecast_chart("
end_marker = "\n    def "  # Next method

start_idx = content.find(start_marker)
if start_idx == -1:
    print("ERROR: Could not find forecast_chart method!")
    exit(1)

# Find the next method after forecast_chart
end_idx = content.find(end_marker, start_idx + len(start_marker))
if end_idx == -1:
    # No next method found, use end of class
    end_idx = len(content)

print(f"Found forecast_chart at pos {start_idx}-{end_idx}")
print(f"Method preview: {content[start_idx:start_idx+50]}...")

# Replace method
new_content = content[:start_idx] + new_method + content[end_idx:]

with open("/app/app/services/analytics/charts.py", "w") as f:
    f.write(new_content)

print("Method replaced!")

# Test immediately
import sys
sys.path.insert(0, "/app")

# Clear any cached modules
for key in list(sys.modules.keys()):
    if "analytics" in key:
        del sys.modules[key]

try:
    from app.services.analytics.charts import CVEChartGenerator
    gen = CVEChartGenerator()
    
    # Test with same types as real data
    import numpy as np
    result = gen.forecast_chart(
        historical_dates=["2024-01", "2024-02", "2024-03"],
        historical_values=[100.0, 110.0, 120.0],
        forecast_dates=["2024-04", "2024-05", "2024-06"],
        forecast_values=[125.0, 130.0, 128.0],
        lower_bound=[115.0, 120.0, 118.0],
        upper_bound=[135.0, 140.0, 138.0],
        method="Linear Trend"
    )
    
    if result.get("error"):
        print(f"TEST FAILED: {result['error']}")
    else:
        traces = len(result.get("data", []))
        print(f"TEST PASSED: {traces} traces")
        for t in result.get("data", []):
            print(f"  - {t.get('name','?')}: x={len(t.get('x',[]))} y={len(t.get('y',[]))}")
            
except Exception as e:
    import traceback
    traceback.print_exc()
