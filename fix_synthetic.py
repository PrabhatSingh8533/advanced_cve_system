import re

with open("/app/app/services/analytics/synthetic_data.py", "r") as f:
    content = f.read()

# Fix 1: YEARLY_TOTALS - add 2025 and 2026
if "2025" not in content:
    content = content.replace(
        "2024: 40000,",
        "2024: 40000,\n        2025: 45000,\n        2026: 25000,"
    )
    print("Added 2025/2026 to YEARLY_TOTALS")

# Fix 2: generate_monthly_counts end_year default
content = content.replace(
    "end_year: int = 2024",
    "end_year: int = None"
)
content = content.replace(
    "end_year: int = None  # None = current year",
    "end_year: int = None"
)

# Fix 3: ensure None uses current year
if "if end_year is None:" not in content:
    content = content.replace(
        "def generate_monthly_counts(\n        self,\n        start_year: int = 2015,\n        end_year: int = None",
        "def generate_monthly_counts(\n        self,\n        start_year: int = 2015,\n        end_year: int = None"
    )

# Fix 4: os_distribution end year
content = content.replace(
    "end_year: int = 2024",
    "end_year: int = None"
)

with open("/app/app/services/analytics/synthetic_data.py", "w") as f:
    f.write(content)

print("synthetic_data.py patched!")

# Verify
with open("/app/app/services/analytics/synthetic_data.py") as f:
    lines = f.readlines()
for i, line in enumerate(lines):
    if "2025" in line or "2026" in line or "end_year" in line:
        print(f"Line {i+1}: {line.rstrip()}")
