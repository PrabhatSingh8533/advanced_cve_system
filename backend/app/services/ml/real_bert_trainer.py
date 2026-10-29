"""
Real Data BERT Trainer.
Trains ONLY on real NVD CVE data. No synthetic data.
"""

import json
import numpy as np
import torch
from pathlib import Path
from torch.utils.data import DataLoader, TensorDataset, random_split
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    get_cosine_schedule_with_warmup
)
from torch.optim import AdamW
from sklearn.metrics import (
    f1_score, accuracy_score,
    classification_report, confusion_matrix
)
from loguru import logger


class RealDataBERTTrainer:
    """
    BERT trainer using ONLY real NVD CVE data.
    Honest training with real metrics.
    """

    MODEL_NAME = "distilbert-base-uncased"

    def __init__(self, model_dir: str = "app/models/bert_real"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        )
        logger.info(
            f"RealDataBERTTrainer | Device: {self.device}"
        )

    def train(
        self,
        dataset: list,
        label_map: dict,
        epochs: int = 5,
        batch_size: int = 16,
        learning_rate: float = 2e-5,
        max_length: int = 256,
        test_split: float = 0.2
    ) -> dict:
        """
        Train on REAL CVE data.

        Args:
            dataset: Real CVE samples from NVD
            label_map: {exploit_type: label_id}
            epochs: Training epochs
            test_split: Fraction for test set (honest evaluation)
        """
        if not dataset:
            raise ValueError("No training data provided!")

        logger.info("=" * 60)
        logger.info("REAL DATA BERT TRAINING")
        logger.info(f"Samples: {len(dataset)} (all from NVD API)")
        logger.info(f"Classes: {len(label_map)}")
        logger.info(f"Device: {self.device}")
        logger.info("=" * 60)

        # ── 1. Tokenize real CVE descriptions ─────────────────
        logger.info("Tokenizing real CVE descriptions...")
        tokenizer = AutoTokenizer.from_pretrained(self.MODEL_NAME)

        texts = [d["text"] for d in dataset]
        label_ids = [d["label_id"] for d in dataset]

        enc = tokenizer(
            texts,
            max_length=max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        )

        full_dataset = TensorDataset(
            enc["input_ids"],
            enc["attention_mask"],
            torch.tensor(label_ids, dtype=torch.long)
        )

        # ── 2. Train / Validation / Test Split ────────────────
        # Use proper 3-way split for honest evaluation
        n = len(full_dataset)
        test_n = max(len(label_map), int(test_split * n))
        val_n = max(len(label_map), int(0.1 * n))
        train_n = n - val_n - test_n

        if train_n < len(label_map):
            raise ValueError(
                f"Not enough data! Need at least "
                f"{len(label_map) * 3} samples, got {n}"
            )

        train_ds, val_ds, test_ds = random_split(
            full_dataset,
            [train_n, val_n, test_n],
            generator=torch.Generator().manual_seed(42)
        )

        logger.info(
            f"Split → Train: {train_n} | "
            f"Val: {val_n} | Test: {test_n}"
        )

        train_loader = DataLoader(
            train_ds, batch_size=batch_size, shuffle=True
        )
        val_loader = DataLoader(val_ds, batch_size=batch_size * 2)
        test_loader = DataLoader(test_ds, batch_size=batch_size * 2)

        # ── 3. Compute class weights ───────────────────────────
        class_counts = [0] * len(label_map)
        for d in dataset:
            class_counts[d["label_id"]] += 1

        counts_tensor = torch.tensor(
            class_counts, dtype=torch.float
        )
        class_weights = (
            counts_tensor.sum() / (len(label_map) * counts_tensor)
        ).to(self.device)

        logger.info(f"Class counts: {dict(zip(label_map.keys(), class_counts))}")

        # ── 4. Model ───────────────────────────────────────────
        logger.info("Loading DistilBERT...")
        model = AutoModelForSequenceClassification.from_pretrained(
            self.MODEL_NAME,
            num_labels=len(label_map),
            ignore_mismatched_sizes=True
        )
        model.to(self.device)

        # ── 5. Optimizer ───────────────────────────────────────
        optimizer = AdamW(
            model.parameters(),
            lr=learning_rate,
            weight_decay=0.01
        )

        total_steps = len(train_loader) * epochs
        scheduler = get_cosine_schedule_with_warmup(
            optimizer,
            num_warmup_steps=total_steps // 10,
            num_training_steps=total_steps
        )

        loss_fn = torch.nn.CrossEntropyLoss(weight=class_weights)

        # ── 6. Training Loop ───────────────────────────────────
        best_val_f1 = 0.0
        history = []
        id_to_label = {v: k for k, v in label_map.items()}

        for epoch in range(epochs):
            logger.info(f"\n{'='*50}")
            logger.info(f"EPOCH {epoch+1}/{epochs}")

            # Train
            model.train()
            train_losses = []
            train_preds = []
            train_true = []

            for batch in train_loader:
                iids = batch[0].to(self.device)
                mask = batch[1].to(self.device)
                labs = batch[2].to(self.device)

                optimizer.zero_grad()
                out = model(input_ids=iids, attention_mask=mask)
                loss = loss_fn(out.logits, labs)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(
                    model.parameters(), 1.0
                )
                optimizer.step()
                scheduler.step()

                train_losses.append(loss.item())
                preds = torch.argmax(out.logits, 1)
                train_preds.extend(preds.cpu().tolist())
                train_true.extend(labs.cpu().tolist())

            # Validate
            model.eval()
            val_preds = []
            val_true = []

            with torch.no_grad():
                for batch in val_loader:
                    iids = batch[0].to(self.device)
                    mask = batch[1].to(self.device)
                    labs = batch[2].to(self.device)
                    out = model(input_ids=iids, attention_mask=mask)
                    preds = torch.argmax(out.logits, 1)
                    val_preds.extend(preds.cpu().tolist())
                    val_true.extend(labs.cpu().tolist())

            train_f1 = f1_score(
                train_true, train_preds,
                average="macro", zero_division=0
            )
            val_f1 = f1_score(
                val_true, val_preds,
                average="macro", zero_division=0
            )
            val_acc = accuracy_score(val_true, val_preds)

            epoch_data = {
                "epoch": epoch + 1,
                "train_loss": round(float(np.mean(train_losses)), 4),
                "train_f1": round(float(train_f1), 4),
                "val_f1": round(float(val_f1), 4),
                "val_accuracy": round(float(val_acc), 4),
                "data_source": "NVD API (real)"
            }
            history.append(epoch_data)

            logger.info(
                f"Train F1: {train_f1:.4f} | "
                f"Val F1: {val_f1:.4f} | "
                f"Val Acc: {val_acc:.4f}"
            )

            # Per-class report
            label_names = [
                id_to_label[i] for i in range(len(label_map))
            ]
            report = classification_report(
                val_true, val_preds,
                target_names=label_names,
                zero_division=0,
                digits=3
            )
            logger.info(f"\nValidation Report:\n{report}")

            if val_f1 >= best_val_f1:
                best_val_f1 = val_f1
                self._save(model, tokenizer, label_map, history)
                logger.success(
                    f"✅ Best model! Val F1={best_val_f1:.4f}"
                )

        # ── 7. Final Test Evaluation (HONEST) ─────────────────
        logger.info("\n" + "="*60)
        logger.info("FINAL TEST EVALUATION (HELD-OUT SET)")
        logger.info("="*60)

        # Load best model for test evaluation
        best_model = AutoModelForSequenceClassification.from_pretrained(
            str(self.model_dir / "cve_classifier_real")
        )
        best_model.to(self.device)
        best_model.eval()

        test_preds = []
        test_true = []

        with torch.no_grad():
            for batch in test_loader:
                iids = batch[0].to(self.device)
                mask = batch[1].to(self.device)
                labs = batch[2].to(self.device)
                out = best_model(input_ids=iids, attention_mask=mask)
                preds = torch.argmax(out.logits, 1)
                test_preds.extend(preds.cpu().tolist())
                test_true.extend(labs.cpu().tolist())

        test_f1 = float(f1_score(
            test_true, test_preds,
            average="macro", zero_division=0
        ))
        test_acc = float(accuracy_score(test_true, test_preds))

        test_report = classification_report(
            test_true, test_preds,
            target_names=label_names,
            zero_division=0,
            digits=3,
            output_dict=True
        )

        conf_matrix = confusion_matrix(
            test_true, test_preds
        ).tolist()

        logger.info(
            f"\nTEST SET RESULTS (honest, unseen data):\n"
            f"  F1 Score (Macro): {test_f1:.4f}\n"
            f"  Accuracy:         {test_acc:.4f}\n"
        )

        final_report = classification_report(
            test_true, test_preds,
            target_names=label_names,
            zero_division=0,
            digits=3
        )
        logger.info(f"Test Report:\n{final_report}")

        results = {
            "data_source": "NVD API - Real CVE descriptions",
            "training_samples": train_n,
            "validation_samples": val_n,
            "test_samples": test_n,
            "total_samples": n,
            "num_classes": len(label_map),
            "label_map": label_map,
            "class_distribution": dict(
                zip(label_map.keys(), class_counts)
            ),
            "best_val_f1": round(best_val_f1, 4),
            "test_f1_macro": round(test_f1, 4),
            "test_accuracy": round(test_acc, 4),
            "test_report": test_report,
            "confusion_matrix": conf_matrix,
            "training_history": history,
            "model": self.MODEL_NAME,
            "note": "All metrics on real NVD data - no synthetic"
        }

        # Save results
        with open(
            self.model_dir / "real_training_results.json", "w"
        ) as f:
            json.dump(results, f, indent=2)

        return results

    def _save(self, model, tokenizer, label_map, history):
        """Save model artifacts."""
        path = self.model_dir / "cve_classifier_real"
        path.mkdir(exist_ok=True)
        model.save_pretrained(str(path))
        tokenizer.save_pretrained(str(path))
        with open(path / "label_map.json", "w") as f:
            json.dump(label_map, f, indent=2)
        with open(path / "history.json", "w") as f:
            json.dump(history, f, indent=2)
        logger.info(f"Model saved → {path}")

    def predict(self, text: str) -> dict:
        """Predict on real text using real-trained model."""
        path = self.model_dir / "cve_classifier_real"
        if not path.exists():
            raise FileNotFoundError(
                "Real model not trained yet. "
                "Use POST /api/bert/train-real"
            )

        with open(path / "label_map.json") as f:
            label_map = json.load(f)

        tokenizer = AutoTokenizer.from_pretrained(str(path))
        model = AutoModelForSequenceClassification.from_pretrained(
            str(path)
        )
        model.to(self.device)
        model.eval()

        inputs = tokenizer(
            text,
            max_length=256,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        )

        with torch.no_grad():
            out = model(
                input_ids=inputs["input_ids"].to(self.device),
                attention_mask=inputs["attention_mask"].to(self.device)
            )

        probs = torch.softmax(out.logits[0], dim=0)
        pred_id = int(torch.argmax(probs).item())
        id2label = {v: k for k, v in label_map.items()}

        return {
            "predicted_label": id2label.get(pred_id, "Unknown"),
            "confidence": round(float(probs[pred_id]), 4),
            "all_probabilities": dict(
                sorted(
                    {
                        id2label.get(i, f"class_{i}"): round(
                            float(p), 4
                        )
                        for i, p in enumerate(probs)
                    }.items(),
                    key=lambda x: x[1],
                    reverse=True
                )
            ),
            "data_source": "Trained on NVD API real data"
        }
