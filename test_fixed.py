import sys
sys.path.insert(0, "/app")
from app.db.base import Base
from app.db.models.cwe import CWE
from app.db.models.cve import CVE
from app.db.session import SessionLocal
from app.services.ml.severity.predictor import CVESSeverityPredictor

pred = CVESSeverityPredictor()
db   = SessionLocal()

print("=" * 65)
print("  SEVERITY MODEL - EXTREME CLASS TEST")
print("=" * 65)

def sev(s):
    if s >= 9.0: return "CRITICAL"
    if s >= 7.0: return "HIGH"
    if s >= 4.0: return "MEDIUM"
    return "LOW"

# Test CRITICAL
print("\n--- CRITICAL CVEs (True CVSS >= 9.0) ---")
crits = db.query(CVE).filter(
    CVE.cvss_score >= 9.0,
    CVE.description.isnot(None),
    CVE.cvss_score.isnot(None)
).limit(15).all()

c_correct = 0
for cve in crits:
    r     = pred.predict_ensemble(cve.description[:300])
    ok    = r["severity"] == "CRITICAL"
    if ok: c_correct += 1
    icon  = "✅" if ok else "❌"
    boost = r["components"].get("keyword_boost", 0) if "components" in r else 0
    print(f"{icon} True={cve.cvss_score} Pred={r['cvss_score']}({r['severity']}) Boost={boost} | {cve.cve_id}")

c_acc = round(c_correct/len(crits)*100, 1) if crits else 0
print(f"\nCRITICAL Accuracy: {c_correct}/{len(crits)} = {c_acc}%")

# Test LOW
print("\n--- LOW CVEs (True CVSS < 4.0) ---")
lows = db.query(CVE).filter(
    CVE.cvss_score < 4.0,
    CVE.cvss_score > 0,
    CVE.description.isnot(None)
).limit(15).all()

l_correct = 0
for cve in lows:
    r    = pred.predict_ensemble(cve.description[:300])
    ok   = r["severity"] == "LOW"
    if ok: l_correct += 1
    icon = "✅" if ok else "❌"
    boost = r["components"].get("keyword_boost", 0) if "components" in r else 0
    print(f"{icon} True={cve.cvss_score} Pred={r['cvss_score']}({r['severity']}) Boost={boost} | {cve.cve_id}")

l_acc = round(l_correct/len(lows)*100, 1) if lows else 0
print(f"\nLOW Accuracy: {l_correct}/{len(lows)} = {l_acc}%")

# Test HIGH + MEDIUM
print("\n--- HIGH CVEs ---")
highs = db.query(CVE).filter(
    CVE.cvss_score >= 7.0,
    CVE.cvss_score < 9.0,
    CVE.description.isnot(None)
).limit(10).all()

h_correct = sum(
    1 for cve in highs
    if pred.predict_ensemble(cve.description[:300])["severity"] == "HIGH"
)
h_acc = round(h_correct/len(highs)*100, 1) if highs else 0
print(f"HIGH Accuracy: {h_correct}/{len(highs)} = {h_acc}%")

print("\n--- MEDIUM CVEs ---")
meds = db.query(CVE).filter(
    CVE.cvss_score >= 4.0,
    CVE.cvss_score < 7.0,
    CVE.description.isnot(None)
).limit(10).all()

m_correct = sum(
    1 for cve in meds
    if pred.predict_ensemble(cve.description[:300])["severity"] == "MEDIUM"
)
m_acc = round(m_correct/len(meds)*100, 1) if meds else 0
print(f"MEDIUM Accuracy: {m_correct}/{len(meds)} = {m_acc}%")

print()
print("=" * 65)
print("OVERALL SUMMARY:")
print(f"  CRITICAL : {c_acc}%  (was 0% before fix)")
print(f"  HIGH     : {h_acc}%")
print(f"  MEDIUM   : {m_acc}%")
print(f"  LOW      : {l_acc}%  (was 0% before fix)")
print("=" * 65)

db.close()