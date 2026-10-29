"""
CVE Severity Predictor - Feature-Compatible Version.
Auto-detects keyword feature count from saved scaler.
"""

import json
import random
import pickle
import re
import numpy as np
from pathlib import Path
from loguru import logger


class CVESSeverityPredictor:

    def __init__(self, model_dir: str = "app/models/severity"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self._fe_cache   = None
        self._cl_cache   = None
        self._tr_cache   = None
        self._kw_count   = None  # Auto-detected

    @staticmethod
    def score_to_severity(score: float) -> str:
        score = float(score)
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        return "LOW"

    def is_trained(self) -> bool:
        return (
            (self.model_dir / "randomforest_model.pkl").exists() and
            (self.model_dir / "transformer_regressor.pt").exists() and
            (self.model_dir / "feature_extractor.pkl").exists()
        )

    def _load_fe(self):
        """Load feature extractor and auto-detect kw count."""
        if self._fe_cache is not None:
            return self._fe_cache

        fe_path = self.model_dir / "feature_extractor.pkl"
        if not fe_path.exists():
            raise RuntimeError("Feature extractor missing.")

        with open(fe_path, "rb") as f:
            fe = pickle.load(f)

        tfidf  = fe["tfidf"]
        scaler = fe["scaler"]

        # Auto-detect keyword feature count
        tfidf_n      = len(tfidf.vocabulary_)
        total_n      = scaler.n_features_in_
        self._kw_count = total_n - tfidf_n

        logger.info(
            f"Feature extractor loaded: "
            f"tfidf={tfidf_n} kw={self._kw_count} "
            f"total={total_n}"
        )

        self._fe_cache = (tfidf, scaler)
        return self._fe_cache

    def _keyword_features(self, text: str) -> np.ndarray:
        """
        Build keyword features to match saved scaler.
        Auto-adjusts count based on what was trained.
        """
        t = text.lower()
        n = self._kw_count or 13

        # Base 13 features (always present)
        base = [
            1 if any(k in t for k in ["remote code execution","rce","arbitrary code"]) else 0,
            1 if any(k in t for k in ["sql injection","sqli"]) else 0,
            1 if any(k in t for k in ["cross-site scripting","xss"]) else 0,
            1 if any(k in t for k in ["buffer overflow","heap overflow"]) else 0,
            1 if any(k in t for k in ["privilege escalation","root access"]) else 0,
            1 if "unauthenticated" in t else 0,
            1 if "remote" in t else 0,
            1 if "local" in t else 0,
            1 if "physical" in t else 0,
            1 if "minor" in t else 0,
            1 if "critical" in t else 0,
            1 if "complete" in t else 0,
            float(len(t)) / 500.0,
        ]

        # Extra features if scaler expects more
        extra_14 = 1 if "no user interaction" in t else 0
        extra_15 = 1 if "wormable" in t or "zero-click" in t else 0
        extra_16 = 1 if any(k in t for k in ["denial of service","dos"]) else 0
        extra_17 = 1 if "authentication bypass" in t else 0
        extra_18 = 1 if any(k in t for k in ["information disclosure","data leak"]) else 0

        extras = [
            extra_14, extra_15, extra_16, extra_17, extra_18
        ]

        # Use exactly n features
        all_features = base + extras
        features = all_features[:n]

        # Pad if needed
        while len(features) < n:
            features.append(0.0)

        return np.array([features], dtype=np.float32)

    def _keyword_boost(self, text: str) -> float:
        """Keyword boost for extreme classes."""
        t = text.lower()

        # CRITICAL patterns
        critical_patterns = [
            r"unauthenticated.*remote code execution",
            r"remote code execution.*unauthenticated",
            r"pre.?auth.*rce",
            r"zero.click",
            r"wormable",
            r"jndi.*execut",
            r"no user interaction.*code execution",
            r"code execution.*no user interaction",
        ]
        for p in critical_patterns:
            if re.search(p, t):
                return 2.0

        # LOW patterns
        low_patterns = [
            r"requires? physical access",
            r"physical access (is )?required",
            r"no security impact",
            r"informational.*severity",
            r"trivial.*impact",
            r"not a security (vulnerability|issue)",
        ]
        for p in low_patterns:
            if re.search(p, t):
                return -2.5

        # Soft signals
        boost = 0.0
        if "unauthenticated" in t and "remote" in t:
            boost += 1.0
        if "remote code execution" in t:
            boost += 1.0
        if "local" in t and "only" in t:
            boost -= 0.5
        if "physical" in t:
            boost -= 1.0
        if "minor" in t or "minimal" in t:
            boost -= 0.5

        return boost

    def predict_classical(
        self, text: str, model_name: str = None
    ) -> dict:
        """Predict using classical ML."""
        tfidf, scaler = self._load_fe()

        # TF-IDF features
        tfidf_feat = tfidf.transform([text[:300]]).toarray()

        # Keyword features (auto-sized)
        kw = self._keyword_features(text)

        # Combine
        combined = np.hstack([tfidf_feat, kw])

        # Verify shape matches scaler
        expected = scaler.n_features_in_
        actual   = combined.shape[1]

        if actual != expected:
            logger.warning(
                f"Feature mismatch: got {actual}, expected {expected}. "
                f"Adjusting..."
            )
            if actual < expected:
                # Pad with zeros
                pad = np.zeros((1, expected - actual))
                combined = np.hstack([combined, pad])
            else:
                # Trim
                combined = combined[:, :expected]

        X = scaler.transform(combined)

        # Load model
        if self._cl_cache is None:
            results_path = self.model_dir / "classical_results.json"
            best = "RandomForest"
            if results_path.exists():
                with open(results_path) as f:
                    best = json.load(f).get("best_model", "RandomForest")

            mp = self.model_dir / f"{best.lower()}_model.pkl"
            if not mp.exists():
                mp = self.model_dir / "randomforest_model.pkl"

            with open(mp, "rb") as f:
                self._cl_cache = (pickle.load(f), best)

        model, best_name = self._cl_cache
        score = float(np.clip(model.predict(X)[0], 0.1, 10.0))

        # Apply keyword boost
        boost = self._keyword_boost(text)
        score = round(float(np.clip(score + boost, 0.1, 10.0)), 1)

        return {
            "cvss_score": score,
            "severity": self.score_to_severity(score),
            "model": model_name or best_name,
            "method": "classical_ml"
        }

    def predict_transformer(self, text: str) -> dict:
        """Predict using transformer."""
        import torch
        import torch.nn as nn
        from transformers import AutoModel, AutoTokenizer

        mp = self.model_dir / "transformer_regressor.pt"
        tp = self.model_dir / "tokenizer"

        if not mp.exists():
            raise RuntimeError("Transformer not trained.")

        if self._tr_cache is None:
            MODEL     = "distilbert-base-uncased"
            tokenizer = AutoTokenizer.from_pretrained(str(tp))
            bert      = AutoModel.from_pretrained(MODEL)
            h         = bert.config.hidden_size

            class Model(nn.Module):
                def __init__(self, bert, h):
                    super().__init__()
                    self.bert = bert
                    self.head = nn.Sequential(
                        nn.LayerNorm(h),
                        nn.Linear(h, 256), nn.GELU(),
                        nn.Dropout(0.15),
                        nn.Linear(256, 64), nn.GELU(),
                        nn.Dropout(0.1),
                        nn.Linear(64, 1),
                        nn.Sigmoid()
                    )
                def forward(self, iids, mask):
                    out = self.bert(
                        input_ids=iids, attention_mask=mask
                    )
                    m = mask.unsqueeze(-1).float()
                    pooled = (
                        out.last_hidden_state * m
                    ).sum(1) / m.sum(1).clamp(min=1e-9)
                    return self.head(pooled).squeeze(-1)

            device = torch.device(
                "cuda" if torch.cuda.is_available() else "cpu"
            )
            model = Model(bert, h)
            model.load_state_dict(
                torch.load(mp, map_location=device)
            )
            model.to(device)
            model.eval()
            self._tr_cache = (model, tokenizer, device)

        model, tokenizer, device = self._tr_cache

        inputs = tokenizer(
            text, max_length=128, padding="max_length",
            truncation=True, return_tensors="pt"
        )
        iids = inputs["input_ids"].to(device)
        mask = inputs["attention_mask"].to(device)

        with torch.no_grad():
            pred = model(iids, mask).item()

        score = float(np.clip(pred * 10.0, 0.1, 10.0))

        # Apply keyword boost
        boost = self._keyword_boost(text)
        score = round(float(np.clip(score + boost, 0.1, 10.0)), 1)

        return {
            "cvss_score": score,
            "severity": self.score_to_severity(score),
            "model": "distilbert-regressor",
            "method": "transformer"
        }

    def predict_ensemble(self, text: str) -> dict:
        """Ensemble: 35% Classical + 65% Transformer."""
        cl_ok = True
        tr_ok = True
        cl = None
        tr = None

        try:
            cl = self.predict_classical(text)
        except Exception as e:
            logger.warning(f"Classical failed: {e}")
            cl_ok = False

        try:
            tr = self.predict_transformer(text)
        except Exception as e:
            logger.warning(f"Transformer failed: {e}")
            tr_ok = False

        if cl_ok and tr_ok:
            score = round(
                0.35 * cl["cvss_score"] +
                0.65 * tr["cvss_score"], 1
            )
            score = float(np.clip(score, 0.1, 10.0))
            return {
                "cvss_score": score,
                "severity": self.score_to_severity(score),
                "model": "ensemble",
                "method": "ensemble",
                "components": {
                    "classical":    cl["cvss_score"],
                    "transformer":  tr["cvss_score"],
                    "keyword_boost": self._keyword_boost(text)
                }
            }
        elif cl_ok:
            return cl
        elif tr_ok:
            return tr
        else:
            raise RuntimeError(
                "All models failed. Retrain needed."
            )

    def train_all(
        self,
        samples_per_severity: int = 200,
        epochs: int = 5,
        db=None,
        max_samples: int = 8000
    ) -> dict:
        """Train with balanced real + synthetic data."""
        logger.info("=" * 55)
        logger.info("Severity Training - Balanced Classes")
        logger.info("=" * 55)

        # Reset caches when retraining
        self._fe_cache  = None
        self._cl_cache  = None
        self._tr_cache  = None
        self._kw_count  = None

        all_data = []

        if db:
            try:
                from app.db.models.cve import CVE
                for sev_name, low, high in [
                    ("CRITICAL", 9.0, 10.0),
                    ("HIGH",     7.0,  8.99),
                    ("MEDIUM",   4.0,  6.99),
                    ("LOW",      0.1,  3.99),
                ]:
                    cves = db.query(CVE).filter(
                        CVE.description.isnot(None),
                        CVE.cvss_score >= low,
                        CVE.cvss_score <= high,
                        CVE.cvss_score > 0
                    ).all()

                    samples = [
                        {
                            "text": c.description[:400],
                            "cvss_score": float(c.cvss_score),
                            "source": "real"
                        }
                        for c in cves
                        if c.description
                        and len(c.description) > 20
                        and "** reserved **" not in c.description.lower()
                    ]

                    logger.info(
                        f"  {sev_name}: {len(samples)} real"
                    )
                    random.shuffle(samples)
                    target = samples_per_severity

                    if len(samples) >= target:
                        all_data.extend(samples[:target])
                    elif samples:
                        all_data.extend(samples)
                        extra = random.choices(
                            samples,
                            k=target - len(samples)
                        )
                        all_data.extend(extra)

            except Exception as e:
                logger.error(f"DB error: {e}", exc_info=True)

        # Synthetic supplement
        synthetic = self._generate_synthetic(100)
        all_data.extend(synthetic)
        random.shuffle(all_data)
        all_data = all_data[:max_samples]

        dist = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for d in all_data:
            s = d["cvss_score"]
            if s >= 9.0:   dist["CRITICAL"] += 1
            elif s >= 7.0: dist["HIGH"]     += 1
            elif s >= 4.0: dist["MEDIUM"]   += 1
            else:          dist["LOW"]      += 1

        logger.info(f"Dataset: {len(all_data)} | {dist}")

        texts  = [d["text"] for d in all_data]
        scores = [d["cvss_score"] for d in all_data]

        cl_results = self._train_classical(texts, scores)
        tr_results = self._train_transformer(texts, scores, epochs)

        best_cl = cl_results.get("best_model", "RandomForest")
        cl_mae  = float(
            cl_results.get(best_cl, {}).get("val_mae", 99)
            if isinstance(cl_results.get(best_cl), dict) else 99
        )
        tr_mae  = float(tr_results.get("best_val_mae", 99))
        winner  = (
            "Transformer" if tr_mae < cl_mae
            else f"Classical({best_cl})"
        )

        results = {
            "total_samples": len(all_data),
            "real_samples":  sum(
                1 for d in all_data if d.get("source")=="real"
            ),
            "data_source": "NVD real + synthetic balanced",
            "score_distribution": dist,
            "comparison": {
                "best_classical":  best_cl,
                "classical_mae":   round(cl_mae, 4),
                "transformer_mae": round(tr_mae, 4),
                "winner":          winner,
            }
        }

        with open(
            self.model_dir/"training_results.json","w"
        ) as f:
            json.dump(results, f, indent=2)

        logger.success(
            f"Training done! W={winner} "
            f"CL={cl_mae:.4f} TR={tr_mae:.4f}"
        )
        return results

    def _generate_synthetic(self, n=100) -> list:
        random.seed(42)
        data = []
        examples = {
            "CRITICAL": [
                ("unauthenticated remote code execution via JNDI no user interaction", 10.0),
                ("pre-auth RCE complete system compromise wormable", 10.0),
                ("zero-click remote code execution critical unauthenticated", 10.0),
                ("arbitrary code execution unauthenticated network exploitable", 9.8),
            ],
            "HIGH": [
                ("SQL injection allows database extraction authentication bypass", 8.8),
                ("heap buffer overflow code execution authenticated attacker", 8.1),
                ("privilege escalation to root SUID binary local user", 7.8),
                ("authentication bypass allows admin access", 8.5),
            ],
            "MEDIUM": [
                ("cross-site scripting requires user interaction medium", 6.1),
                ("CSRF state-changing actions authenticated users", 4.3),
                ("path traversal reads files authenticated limited", 5.5),
            ],
            "LOW": [
                ("minor information disclosure local access only no exploitation", 2.0),
                ("requires physical access minimal impact low severity", 1.5),
                ("trivial bypass local authenticated access minimal", 1.8),
                ("informational no exploitation possible low severity", 1.2),
                ("denial of service adjacent network low impact", 3.5),
            ],
        }
        for sev, texts in examples.items():
            for _ in range(n):
                text, score = random.choice(texts)
                noisy = round(min(10.0, max(0.1,
                    score + random.uniform(-0.3, 0.3)
                )), 1)
                data.append({
                    "text":       text,
                    "cvss_score": noisy,
                    "source":     "synthetic"
                })
        return data

    def _train_classical(self, texts, scores) -> dict:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.preprocessing import StandardScaler
        from sklearn.linear_model import Ridge
        from sklearn.ensemble import RandomForestRegressor
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import mean_absolute_error

        X_tr, X_val, y_tr, y_val = train_test_split(
            texts, scores, test_size=0.15, random_state=42
        )

        # Set kw_count BEFORE building features
        self._kw_count = 13

        tfidf = TfidfVectorizer(
            max_features=2000, ngram_range=(1,2),
            sublinear_tf=True, min_df=1
        )
        tr_t  = tfidf.fit_transform(X_tr).toarray()
        val_t = tfidf.transform(X_val).toarray()

        tr_kw  = np.vstack([self._keyword_features(t) for t in X_tr])
        val_kw = np.vstack([self._keyword_features(t) for t in X_val])

        scaler = StandardScaler()
        X_tr_f  = scaler.fit_transform(np.hstack([tr_t,  tr_kw]))
        X_val_f = scaler.transform(    np.hstack([val_t, val_kw]))

        logger.info(
            f"Training features: tfidf={tr_t.shape[1]} "
            f"kw={self._kw_count} total={X_tr_f.shape[1]}"
        )

        with open(self.model_dir/"feature_extractor.pkl","wb") as f:
            pickle.dump({"tfidf":tfidf,"scaler":scaler}, f)

        def sw(s):
            if s >= 9.0 or s < 4.0: return 3.0
            elif s >= 7.0: return 1.5
            else: return 1.0

        w_tr = np.array([sw(s) for s in y_tr])

        results = {}
        best_n  = "RandomForest"
        best_m  = 999.0

        for name, model in [
            ("Ridge", Ridge(alpha=0.5)),
            ("RandomForest", RandomForestRegressor(
                n_estimators=200, max_depth=12,
                n_jobs=-1, random_state=42
            )),
        ]:
            try:
                model.fit(X_tr_f, y_tr, sample_weight=w_tr)
                vp  = np.clip(model.predict(X_val_f), 0.1, 10.0)
                mae = float(mean_absolute_error(y_val, vp))

                def sev(s):
                    if s>=9: return "C"
                    if s>=7: return "H"
                    if s>=4: return "M"
                    return "L"

                sev_acc  = float(np.mean([sev(p)==sev(t) for p,t in zip(vp,y_val)]))
                crit_acc = float(np.mean([sev(p)=="C" for p,t in zip(vp,y_val) if t>=9])) if any(t>=9 for t in y_val) else 0
                low_acc  = float(np.mean([sev(p)=="L" for p,t in zip(vp,y_val) if t<4]))  if any(t<4  for t in y_val) else 0

                logger.info(
                    f"  {name}: MAE={mae:.4f} "
                    f"Sev={sev_acc:.4f} "
                    f"Crit={crit_acc:.4f} "
                    f"Low={low_acc:.4f}"
                )

                results[name] = {
                    "val_mae": round(mae,4),
                    "severity_accuracy":  round(sev_acc, 4),
                    "critical_accuracy":  round(crit_acc,4),
                    "low_accuracy":       round(low_acc, 4),
                    "status": "trained"
                }

                with open(
                    self.model_dir/f"{name.lower()}_model.pkl","wb"
                ) as f:
                    pickle.dump(model, f)

                if mae < best_m:
                    best_m = mae
                    best_n = name

            except Exception as e:
                logger.error(f"  {name}: {e}")
                results[name] = {"status":"failed","error":str(e)}

        results["best_model"] = best_n
        with open(self.model_dir/"classical_results.json","w") as f:
            json.dump(results, f, indent=2)

        logger.success(f"Classical: Best={best_n} MAE={best_m:.4f}")
        return results

    def _train_transformer(self, texts, scores, epochs=5) -> dict:
        import torch, torch.nn as nn
        from transformers import AutoModel, AutoTokenizer
        from transformers import get_cosine_schedule_with_warmup
        from torch.optim import AdamW
        from torch.utils.data import (
            DataLoader, TensorDataset,
            WeightedRandomSampler, random_split
        )
        from sklearn.metrics import mean_absolute_error

        device    = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        MODEL     = "distilbert-base-uncased"
        tokenizer = AutoTokenizer.from_pretrained(MODEL)

        enc = tokenizer(
            texts, max_length=128, padding="max_length",
            truncation=True, return_tensors="pt"
        )
        scores_t = torch.tensor([s/10.0 for s in scores], dtype=torch.float32)
        dataset  = TensorDataset(enc["input_ids"], enc["attention_mask"], scores_t)

        n = len(dataset)
        val_n   = max(50, int(0.15*n))
        train_n = n - val_n

        train_ds, val_ds = random_split(
            dataset, [train_n, val_n],
            generator=torch.Generator().manual_seed(42)
        )

        w = [3.0 if (scores[i]>=9 or scores[i]<4) else 1.5 if scores[i]>=7 else 1.0
             for i in range(train_n)]
        sampler = WeightedRandomSampler(w, len(w), replacement=True)

        train_loader = DataLoader(train_ds, batch_size=16, sampler=sampler)
        val_loader   = DataLoader(val_ds,   batch_size=32)

        bert = AutoModel.from_pretrained(MODEL)
        h    = bert.config.hidden_size

        class Model(nn.Module):
            def __init__(self, bert, h):
                super().__init__()
                self.bert = bert
                self.head = nn.Sequential(
                    nn.LayerNorm(h), nn.Linear(h,256), nn.GELU(), nn.Dropout(0.15),
                    nn.Linear(256,64), nn.GELU(), nn.Dropout(0.1),
                    nn.Linear(64,1), nn.Sigmoid()
                )
            def forward(self, iids, mask):
                out = self.bert(input_ids=iids, attention_mask=mask)
                m   = mask.unsqueeze(-1).float()
                return self.head((out.last_hidden_state*m).sum(1)/m.sum(1).clamp(min=1e-9)).squeeze(-1)

        model = Model(bert, h).to(device)

        def loss_fn(p, t):
            mse = (p-t)**2
            w   = torch.ones_like(t)
            w[t>=0.9]  = 4.0
            w[t<=0.39] = 4.0
            w[(t>=0.7)&(t<0.9)] = 1.5
            return (mse*w).mean()

        opt   = AdamW(model.parameters(), lr=2e-5, weight_decay=0.01)
        total = len(train_loader)*epochs
        sch   = get_cosine_schedule_with_warmup(opt, total//10, total)

        best_mae = float("inf")
        history  = []

        for ep in range(epochs):
            model.train()
            tp, tt = [], []
            for b in train_loader:
                iids,mask,tgt = b[0].to(device), b[1].to(device), b[2].to(device)
                opt.zero_grad()
                pred = model(iids, mask)
                loss_fn(pred, tgt).backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                opt.step(); sch.step()
                tp.extend((pred.detach().cpu()*10).tolist())
                tt.extend((tgt.cpu()*10).tolist())

            model.eval()
            vp, vt = [], []
            with torch.no_grad():
                for b in val_loader:
                    iids,mask,tgt = b[0].to(device), b[1].to(device), b[2].to(device)
                    vp.extend((model(iids,mask).cpu()*10).tolist())
                    vt.extend((tgt.cpu()*10).tolist())

            tr_mae  = float(mean_absolute_error(tt,tp))
            val_mae = float(mean_absolute_error(vt,vp))

            def sev(s):
                if s>=9: return "C"
                if s>=7: return "H"
                if s>=4: return "M"
                return "L"

            sev_acc  = float(np.mean([sev(p)==sev(t) for p,t in zip(vp,vt)]))
            crit_acc = float(np.mean([sev(p)=="C" for p,t in zip(vp,vt) if t>=9])) if any(t>=9 for t in vt) else 0
            low_acc  = float(np.mean([sev(p)=="L" for p,t in zip(vp,vt) if t<4]))  if any(t<4  for t in vt) else 0

            logger.info(
                f"  Ep{ep+1}/{epochs} ValMAE={val_mae:.4f} "
                f"Sev={sev_acc:.4f} Crit={crit_acc:.4f} Low={low_acc:.4f}"
            )

            history.append({
                "epoch":ep+1, "train_mae":round(tr_mae,4),
                "val_mae":round(val_mae,4),
                "severity_accuracy":round(sev_acc,4),
                "critical_accuracy":round(crit_acc,4),
                "low_accuracy":round(low_acc,4),
            })

            if val_mae < best_mae:
                best_mae = val_mae
                torch.save(model.state_dict(), self.model_dir/"transformer_regressor.pt")
                tokenizer.save_pretrained(str(self.model_dir/"tokenizer"))
                logger.success(f"  ✅ MAE={best_mae:.4f} Crit={crit_acc:.4f} Low={low_acc:.4f}")

        with open(self.model_dir/"transformer_history.json","w") as f:
            json.dump(history, f, indent=2)

        return {"best_val_mae":round(best_mae,4), "history":history}