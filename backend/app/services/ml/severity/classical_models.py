"""
Classical ML Models - Memory Optimized Version.
Removes SVR and XGBoost (memory intensive).
Uses Ridge + RandomForest + GradientBoosting only.
"""

import json
import pickle
import numpy as np
from pathlib import Path
from loguru import logger
from sklearn.linear_model import Ridge
from sklearn.ensemble import (
    RandomForestRegressor,
    GradientBoostingRegressor
)
from sklearn.metrics import mean_absolute_error, mean_squared_error


class ClassicalSeverityModels:
    """Lightweight classical ML for CVSS regression."""

    def __init__(self, model_dir: str = "app/models/severity"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.models = {}
        self.results = {}

    def get_configs(self) -> dict:
        """Lightweight model configs."""
        return {
            "Ridge": Ridge(alpha=1.0),
            "RandomForest": RandomForestRegressor(
                n_estimators=100,  # Reduced from 200
                max_depth=8,       # Reduced from 10
                n_jobs=-1,
                random_state=42
            ),
            "GradientBoosting": GradientBoostingRegressor(
                n_estimators=100,  # Reduced from 200
                max_depth=4,       # Reduced from 5
                learning_rate=0.1,
                random_state=42
            ),
        }

    def train_all(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray
    ) -> dict:
        """Train all models."""
        configs = self.get_configs()
        results = {}

        logger.info(
            f"Training {len(configs)} classical ML models | "
            f"Train: {len(X_train)} | Val: {len(X_val)}"
        )

        for name, model in configs.items():
            logger.info(f"Training {name}...")
            try:
                model.fit(X_train, y_train)

                train_preds = np.clip(
                    model.predict(X_train), 0.0, 10.0
                )
                val_preds = np.clip(
                    model.predict(X_val), 0.0, 10.0
                )

                train_mae = float(
                    mean_absolute_error(y_train, train_preds)
                )
                val_mae = float(
                    mean_absolute_error(y_val, val_preds)
                )
                val_rmse = float(np.sqrt(
                    mean_squared_error(y_val, val_preds)
                ))
                sev_acc = self._severity_accuracy(
                    y_val, val_preds
                )

                result = {
                    "train_mae": round(train_mae, 4),
                    "val_mae": round(val_mae, 4),
                    "val_rmse": round(val_rmse, 4),
                    "severity_accuracy": round(sev_acc, 4),
                    "status": "trained"
                }

                self.models[name] = model
                self.results[name] = result
                results[name] = result

                logger.info(
                    f"  {name}: MAE={val_mae:.4f} | "
                    f"RMSE={val_rmse:.4f} | "
                    f"SevAcc={sev_acc:.4f}"
                )

            except Exception as e:
                logger.error(f"  {name} failed: {e}")
                results[name] = {"status": "failed", "error": str(e)}

        # Find best
        trained = [
            k for k, v in results.items()
            if v.get("status") == "trained"
        ]

        if trained:
            best = min(
                trained,
                key=lambda k: results[k]["val_mae"]
            )
            self.results["best_model"] = best
            results["best_model"] = best
            logger.success(
                f"Best: {best} | "
                f"MAE={results[best]['val_mae']:.4f}"
            )

        self.save_all()
        self.save_results(results)
        return results

    def _severity_accuracy(self, y_true, y_pred) -> float:
        """Check if severity category is correct."""
        def sev(s):
            if s >= 9.0: return "C"
            if s >= 7.0: return "H"
            if s >= 4.0: return "M"
            return "L"
        correct = sum(
            sev(t) == sev(p)
            for t, p in zip(y_true, y_pred)
        )
        return correct / len(y_true) if y_true else 0.0

    def predict(
        self, X: np.ndarray, model_name: str = None
    ) -> np.ndarray:
        """Predict using best model."""
        if not self.models:
            self.load_all()
        name = model_name or self.results.get(
            "best_model", "RandomForest"
        )
        if name not in self.models:
            name = list(self.models.keys())[0]
        return np.clip(self.models[name].predict(X), 0.0, 10.0)

    def save_all(self):
        """Save all models."""
        for name, model in self.models.items():
            path = self.model_dir / f"{name.lower()}_model.pkl"
            with open(path, "wb") as f:
                pickle.dump(model, f)
        logger.info(f"Saved {len(self.models)} models")

    def load_all(self):
        """Load saved models."""
        for name in ["Ridge", "RandomForest", "GradientBoosting"]:
            path = self.model_dir / f"{name.lower()}_model.pkl"
            if path.exists():
                with open(path, "rb") as f:
                    self.models[name] = pickle.load(f)

        results_path = self.model_dir / "classical_results.json"
        if results_path.exists():
            with open(results_path) as f:
                self.results = json.load(f)

        logger.info(f"Loaded {len(self.models)} models")

    def save_results(self, results: dict):
        """Save results."""
        path = self.model_dir / "classical_results.json"
        with open(path, "w") as f:
            json.dump(results, f, indent=2)
