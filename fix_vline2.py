with open("/app/app/services/analytics/charts.py", "r") as f:
    content = f.read()

import re

# Remove ALL add_vline occurrences (multiline)
content = re.sub(
    r'\s*fig\.add_vline\(.*?\n(?:.*?\n)*?.*?\)',
    '',
    content,
    flags=re.DOTALL
)

# Simpler: just remove lines containing add_vline
lines = content.split("\n")
clean_lines = []
skip = False
for line in lines:
    if "add_vline" in line or "Divider" in line and "add_vline" in "".join(lines[lines.index(line):lines.index(line)+5]):
        # Check if this is a multi-line add_vline
        if "(" in line and ")" not in line:
            skip = True  # Start skipping multiline
        # skip this line
        continue
    if skip:
        if ")" in line:
            skip = False  # End of multiline
        continue
    clean_lines.append(line)

content = "\n".join(clean_lines)

with open("/app/app/services/analytics/charts.py", "w") as f:
    f.write(content)

# Verify
if "add_vline" in content:
    # Hard removal
    content2 = "\n".join([
        l for l in content.split("\n")
        if "add_vline" not in l
    ])
    with open("/app/app/services/analytics/charts.py", "w") as f:
        f.write(content2)
    print("Hard removed add_vline line by line")
else:
    print("add_vline successfully removed")

# Test
import sys
for k in list(sys.modules.keys()):
    if "analytics" in k or "charts" in k:
        del sys.modules[k]

sys.path.insert(0, "/app")
try:
    from app.services.analytics.charts import CVEChartGenerator
    gen = CVEChartGenerator()
    result = gen.forecast_chart(
        historical_dates=["2024-01","2024-02","2024-03"],
        historical_values=[100.0, 110.0, 120.0],
        forecast_dates=["2024-04","2024-05","2024-06"],
        forecast_values=[125.0, 130.0, 128.0],
        lower_bound=[115.0, 120.0, 118.0],
        upper_bound=[135.0, 140.0, 138.0],
        method="ARIMA"
    )
    if result.get("error"):
        print(f"STILL FAILING: {result['error']}")
    else:
        print(f"TEST PASSED: {len(result.get('data',[]))} traces")
except Exception as e:
    import traceback
    traceback.print_exc()
