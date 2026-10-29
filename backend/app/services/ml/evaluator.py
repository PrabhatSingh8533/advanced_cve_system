"""
Model Evaluation and Metrics for BERT CVE Models.
"""

import json
from pathlib import Path
from loguru import logger
import numpy as np
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    accuracy_score,
    precision_score,
    recall_score
)


class CVEModelEvaluator:
    """
    Evaluates trained BERT models with detailed metrics.
    """

    def __init__(self, results_dir: str = "app/data/evaluation"):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def evaluate_classifier(
        self,
        y_true: list,
        y_pred: list,
        label_names: list,
        save: bool = True
    ) -> dict:
        """
        Full evaluation of classification model.

        Args:
            y_true: True label IDs
            y_pred: Predicted label IDs
            label_names: List of class names
            save: Whether to save results to disk

        Returns:
            Complete metrics dictionary
        """
        metrics = {
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "f1_macro": float(
                f1_score(y_true, y_pred, average="macro")
            ),
            "f1_weighted": float(
                f1_score(y_true, y_pred, average="weighted")
            ),
            "precision_macro": float(
                precision_score(
                    y_true, y_pred,
                    average="macro",
                    zero_division=0
                )
            ),
            "recall_macro": float(
                recall_score(
                    y_true, y_pred,
                    average="macro",
                    zero_division=0
                )
            ),
        }

        # Per-class report
        report = classification_report(
            y_true, y_pred,
            target_names=label_names,
            output_dict=True,
            zero_division=0
        )
        metrics["per_class_report"] = report

        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        metrics["confusion_matrix"] = cm.tolist()

        logger.info(
            f"Evaluation Results:\n"
            f"  Accuracy:   {metrics['accuracy']:.4f}\n"
            f"  F1 Macro:   {metrics['f1_macro']:.4f}\n"
            f"  F1 Weighted:{metrics['f1_weighted']:.4f}\n"
            f"  Precision:  {metrics['precision_macro']:.4f}\n"
            f"  Recall:     {metrics['recall_macro']:.4f}"
        )

        if save:
            path = self.results_dir / "classifier_eval.json"
            with open(path, "w") as f:
                json.dump(metrics, f, indent=2)
            logger.info(f"Evaluation saved: {path}")

        return metrics

    def print_report(self, metrics: dict) -> None:
        """Print formatted evaluation report."""
        print("\n" + "=" * 60)
        print("📊 CVE CLASSIFIER EVALUATION REPORT")
        print("=" * 60)
        print(f"  Accuracy:            {metrics['accuracy']:.4f}")
        print(f"  F1 Score (Macro):    {metrics['f1_macro']:.4f}")
        print(f"  F1 Score (Weighted): {metrics['f1_weighted']:.4f}")
        print(f"  Precision (Macro):   {metrics['precision_macro']:.4f}")
        print(f"  Recall (Macro):      {metrics['recall_macro']:.4f}")
        print("=" * 60)

        if "per_class_report" in metrics:
            print("\n📋 Per-Class Results:")
            for label, scores in metrics["per_class_report"].items():
                if isinstance(scores, dict):
                    print(
                        f"  {label:<30} "
                        f"P:{scores.get('precision', 0):.3f} "
                        f"R:{scores.get('recall', 0):.3f} "
                        f"F1:{scores.get('f1-score', 0):.3f}"
                    )