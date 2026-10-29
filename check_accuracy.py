import json
import os
import sys
sys.path.insert(0, "/app")

# Import ALL models first
from app.db.base import Base
from app.db.models.cwe import CWE
from app.db.models.cve import CVE

print("=" * 60)
print("  CVE ANALYSIS SYSTEM - MODEL ACCURACY REPORT")
print("  Data Source: Real NVD API CVE Descriptions")
print("=" * 60)

# BERT Model
print()
print("MODEL 1: BERT Exploit Type Classifier")
print("-" * 60)

bert_path = "app/models/bert_real/real_training_results.json"
if os.path.exists(bert_path):
    with open(bert_path) as f:
        bert = json.load(f)

    train_n  = bert.get("training_samples", 0)
    test_n   = bert.get("test_samples", 0)
    classes  = bert.get("num_classes", 0)
    test_f1  = bert.get("test_f1_macro", 0)
    test_acc = bert.get("test_accuracy", 0)

    print("Algorithm   : DistilBERT (distilbert-base-uncased)")
    print("Train Data  :", train_n, "real NVD CVEs")
    print("Test Data   :", test_n, "unseen CVEs (held-out)")
    print("Classes     :", classes, "exploit types")
    print()
    print("TEST SET RESULTS (Never seen during training):")
    print("  F1 Score (Macro) :", round(test_f1, 4),
          " =", round(test_f1 * 100, 2), "%")
    print("  Accuracy         :", round(test_acc, 4),
          " =", round(test_acc * 100, 2), "%")
    print()

    report = bert.get("test_report", {})
    if report:
        print("Per-Class Results:")
        skip = {"accuracy", "macro avg", "weighted avg"}
        for cls, scores in report.items():
            if isinstance(scores, dict) and cls not in skip:
                f1   = round(scores.get("f1-score", 0), 3)
                prec = round(scores.get("precision", 0), 3)
                rec  = round(scores.get("recall", 0), 3)
                print("  {:<35} F1={} Prec={} Rec={}".format(
                    cls, f1, prec, rec
                ))
        print()
        print("Averages:")
        for avg in ["macro avg", "weighted avg"]:
            if avg in report:
                s    = report[avg]
                f1   = round(s.get("f1-score", 0), 3)
                prec = round(s.get("precision", 0), 3)
                rec  = round(s.get("recall", 0), 3)
                print("  {:<20} F1={} Prec={} Rec={}".format(
                    avg, f1, prec, rec
                ))

    hist = bert.get("training_history", [])
    if hist:
        print()
        print("Training Progress:")
        for h in hist:
            ep  = h.get("epoch", 0)
            tf1 = round(h.get("train_f1", 0), 4)
            vf1 = round(h.get("val_f1", 0), 4)
            acc = round(h.get("val_accuracy", 0), 4)
            print("  Epoch {} : Train F1={} | Val F1={} | Val Acc={}".format(
                ep, tf1, vf1, acc
            ))
else:
    print("File not found:", bert_path)

# Severity Model
print()
print("=" * 60)
print("MODEL 2: CVSS Severity Predictor")
print("-" * 60)

# Get real data count from DB
from app.db.session import SessionLocal

db = SessionLocal()
real_count = db.query(CVE).filter(
    CVE.cvss_score.isnot(None),
    CVE.cvss_score > 0,
    CVE.description.isnot(None)
).count()
db.close()

print("Real NVD CVEs with CVSS:", real_count)

sev_path = "app/models/severity/training_results.json"
if os.path.exists(sev_path):
    with open(sev_path) as f:
        sev = json.load(f)

    total  = sev.get("total_samples", 0)
    source = sev.get("data_source", "N/A")
    comp   = sev.get("comparison", {})
    winner = comp.get("winner", "N/A")
    cl_mae = comp.get("classical_mae", 0)
    tr_mae = comp.get("transformer_mae", 0)

    print("Algorithm   : Ensemble (Classical ML + Transformer)")
    print("Train Data  :", total, "CVEs")
    print("Data Source :", source)
    print()
    print("TEST RESULTS:")
    print("  Transformer MAE :", round(tr_mae, 4),
          "(avg CVSS error on 0-10 scale)")
    print("  Classical MAE   :", round(cl_mae, 4))
    print("  Best Model      :", winner)

    # Transformer history
    tr_hist_path = "app/models/severity/transformer_history.json"
    if os.path.exists(tr_hist_path):
        with open(tr_hist_path) as f:
            tr_hist = json.load(f)
        if tr_hist:
            print()
            print("Transformer Training:")
            for h in tr_hist:
                ep   = h.get("epoch", 0)
                tmae = round(h.get("train_mae", 0), 4)
                vmae = round(h.get("val_mae", 0), 4)
                sacc = h.get("severity_accuracy", 0)
                sacc_str = round(sacc * 100, 2) if sacc else "N/A"
                print("  Epoch {} : TrainMAE={} | ValMAE={} | SevAcc={}%".format(
                    ep, tmae, vmae, sacc_str
                ))

    # Classical
    cl_path = "app/models/severity/classical_results.json"
    if os.path.exists(cl_path):
        with open(cl_path) as f:
            cl = json.load(f)
        best = cl.get("best_model", "N/A")
        print()
        print("Classical ML:")
        print("  Best :", best)
        for name in ["Ridge", "RandomForest", "GradientBoosting"]:
            if name in cl and isinstance(cl[name], dict):
                mae  = round(cl[name].get("val_mae", 0), 4)
                sacc = cl[name].get("severity_accuracy", 0)
                sacc_pct = round(sacc * 100, 2) if sacc else 0
                print("  {} : MAE={} | SevAcc={}%".format(
                    name, mae, sacc_pct
                ))

    # Score distribution from DB
    print()
    print("CVSS Distribution in DB:")
    from app.db.session import SessionLocal
    db = SessionLocal()
    dist = {"CRITICAL":0, "HIGH":0, "MEDIUM":0, "LOW":0}
    cves = db.query(CVE).filter(
        CVE.cvss_score.isnot(None),
        CVE.cvss_score > 0
    ).all()
    total_db = 0
    for c in cves:
        s = float(c.cvss_score)
        total_db += 1
        if s >= 9.0:   dist["CRITICAL"] += 1
        elif s >= 7.0: dist["HIGH"]     += 1
        elif s >= 4.0: dist["MEDIUM"]   += 1
        else:          dist["LOW"]      += 1
    db.close()

    for sev_label, cnt in dist.items():
        pct = round(cnt / total_db * 100, 1) if total_db > 0 else 0
        bar = chr(9608) * int(pct / 3)
        print("  {:<10} {:.<20} {:>6} ({}%)".format(
            sev_label, bar, cnt, pct
        ))

else:
    print("File not found:", sev_path)

print()
print("=" * 60)
print("EVALUATION NOTE:")
print("  All metrics on HELD-OUT test set (unseen during training)")
print("  BERT data: Real NVD CVE descriptions")
print("  Severity data: Real NVD official CVSS scores")
print("  MAE 0-10 scale: Lower = Better")
print("  MAE < 1.0 = Excellent severity prediction")
print("=" * 60)