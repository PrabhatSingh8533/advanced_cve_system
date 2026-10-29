with open("/app/app/services/analytics/charts.py", "r") as f:
    content = f.read()

# Remove the add_vline call completely
import re

# Remove any add_vline block
content = re.sub(
    r'\s*# Divider.*?\n.*?fig\.add_vline\([^)]*\)[^)]*\)',
    '',
    content,
    flags=re.DOTALL
)

# Also remove standalone add_vline calls
content = re.sub(
    r'\s*fig\.add_vline\(.*?\)',
    '',
    content,
    flags=re.DOTALL
)

with open("/app/app/services/analytics/charts.py", "w") as f:
    f.write(content)

print("Removed add_vline!")

# Verify removal
if "add_vline" in content:
    print("WARNING: add_vline still present!")
    idx = content.find("add_vline")
    print(content[max(0,idx-100):idx+200])
else:
    print("Confirmed: add_vline removed")
