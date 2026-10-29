import sys
sys.path.insert(0, "/app")

# Must import ALL models to register relationships
from app.db.base import Base
from app.db.models.cwe import CWE
from app.db.models.cve import CVE
from app.db.session import SessionLocal
from sqlalchemy import func

db = SessionLocal()

total = db.query(CVE).count()

with_cvss = db.query(CVE).filter(
    CVE.cvss_score.isnot(None),
    CVE.cvss_score > 0
).count()

with_sev = db.query(CVE).filter(
    CVE.severity.isnot(None)
).count()

print("=== Real Data Check ===")
print("Total CVEs      :", total)
print("With CVSS score :", with_cvss)
print("With severity   :", with_sev)

# Distribution
dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
usable = 0

cves = db.query(CVE).filter(
    CVE.cvss_score.isnot(None),
    CVE.cvss_score > 0
).all()

for cve in cves:
    if not cve.description or len(cve.description) < 20:
        continue
    if "** reserved **" in cve.description.lower():
        continue

    score = float(cve.cvss_score)
    usable += 1

    if score >= 9.0:   dist["CRITICAL"] += 1
    elif score >= 7.0: dist["HIGH"]     += 1
    elif score >= 4.0: dist["MEDIUM"]   += 1
    else:              dist["LOW"]      += 1

print("Usable samples  :", usable)
print()
print("Score Distribution:")
for sev, cnt in dist.items():
    pct = round(cnt / usable * 100, 1) if usable > 0 else 0
    bar = chr(9608) * int(pct / 3)
    print("  {:<10} {} {} ({}%)".format(sev, bar, cnt, pct))

db.close()