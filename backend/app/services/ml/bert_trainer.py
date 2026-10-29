"""
CVE BERT Trainer - Fixed & Optimized Version.
Uses proper training loop with class weights and better LR.
"""

import json
from pathlib import Path
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, random_split, TensorDataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    get_cosine_schedule_with_warmup
)
from torch.optim import AdamW
from loguru import logger
from sklearn.metrics import (
    f1_score, accuracy_score, classification_report
)
import numpy as np

from app.services.ml.data_generator import CVETrainingDataGenerator


class CVEBERTTrainer:
    """
    Optimized DistilBERT trainer for CVE exploit classification.
    Fixed training loop with:
    - Class-weighted loss (handles imbalance)
    - Cosine LR schedule (better convergence)
    - Lower learning rate (2e-5)
    - More data per class
    """

    MODEL_NAME = "distilbert-base-uncased"

    def __init__(
        self,
        model_dir: str = "app/models/bert",
        device: str = None
    ):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        )
        logger.info(
            f"Trainer | Device: {self.device} | "
            f"Model: {self.MODEL_NAME}"
        )
        self.generator = CVETrainingDataGenerator()

    def train_classifier(
        self,
        epochs: int = 5,
        batch_size: int = 16,
        learning_rate: float = 2e-5,
        max_length: int = 128,
        samples_per_class: int = 80,
        db=None
    ) -> dict:
        """
        Train CVE exploit type classifier.
        Fixed version with proper convergence.
        """
        logger.info("=" * 55)
        logger.info(f"CVE Exploit Classifier Training")
        logger.info(
            f"Model: {self.MODEL_NAME} | "
            f"Epochs: {epochs} | "
            f"LR: {learning_rate}"
        )
        logger.info("=" * 55)

        # ── 1. Build Dataset ───────────────────────────────────
        logger.info("Building training dataset...")
        synthetic = self.generator.generate_classification_dataset(
            samples_per_class=samples_per_class
        )

        db_data = []
        if db:
            try:
                db_data = self.generator.generate_from_db(db)
                logger.info(f"Added {len(db_data)} DB samples")
            except Exception as e:
                logger.warning(f"DB data skipped: {e}")

        all_data = synthetic + db_data
        logger.info(f"Total dataset: {len(all_data)} samples")

        # Log class distribution
        label_map = self.generator.get_label_map()
        num_labels = len(label_map)
        class_counts = [0] * num_labels
        for d in all_data:
            class_counts[d["label_id"]] += 1

        logger.info("Class distribution:")
        id_to_label = self.generator.get_id_label_map()
        for i, count in enumerate(class_counts):
            logger.info(f"  {id_to_label[i]}: {count}")

        # Save dataset
        self.generator.save_dataset(all_data, "train_data.json")

        # ── 2. Tokenize ────────────────────────────────────────
        logger.info(f"Tokenizing with {self.MODEL_NAME}...")
        tokenizer = AutoTokenizer.from_pretrained(self.MODEL_NAME)

        texts = [d["text"] for d in all_data]
        label_ids = [d["label_id"] for d in all_data]

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

        # ── 3. Train/Val Split ─────────────────────────────────
        val_size = max(num_labels * 2, int(0.15 * len(full_dataset)))
        train_size = len(full_dataset) - val_size

        train_ds, val_ds = random_split(
            full_dataset,
            [train_size, val_size],
            generator=torch.Generator().manual_seed(42)
        )

        train_loader = DataLoader(
            train_ds,
            batch_size=batch_size,
            shuffle=True,
            drop_last=False
        )
        val_loader = DataLoader(
            val_ds,
            batch_size=batch_size * 2,
            shuffle=False
        )

        logger.info(
            f"Train: {train_size} | Val: {val_size} samples"
        )

        # ── 4. Model ───────────────────────────────────────────
        logger.info("Loading DistilBERT model...")
        model = AutoModelForSequenceClassification.from_pretrained(
            self.MODEL_NAME,
            num_labels=num_labels,
            ignore_mismatched_sizes=True
        )
        model.to(self.device)

        total_params = sum(
            p.numel() for p in model.parameters()
        )
        trainable = sum(
            p.numel() for p in model.parameters()
            if p.requires_grad
        )
        logger.info(
            f"Parameters: {total_params/1e6:.1f}M total | "
            f"{trainable/1e6:.1f}M trainable"
        )

        # ── 5. Class Weights (handle imbalance) ────────────────
        counts = torch.tensor(class_counts, dtype=torch.float)
        class_weights = (counts.sum() / (num_labels * counts))
        class_weights = class_weights.to(self.device)
        logger.info(f"Class weights computed for balanced training")

        # Loss with class weights
        loss_fn = nn.CrossEntropyLoss(weight=class_weights)

        # ── 6. Optimizer + Cosine Schedule ────────────────────
        # Layer-wise learning rates (classifier gets higher LR)
        no_decay = ["bias", "LayerNorm.weight"]
        optimizer_groups = [
            {
                "params": [
                    p for n, p in model.named_parameters()
                    if not any(nd in n for nd in no_decay)
                ],
                "weight_decay": 0.01,
                "lr": learning_rate
            },
            {
                "params": [
                    p for n, p in model.named_parameters()
                    if any(nd in n for nd in no_decay)
                ],
                "weight_decay": 0.0,
                "lr": learning_rate
            },
        ]

        optimizer = AdamW(optimizer_groups, eps=1e-8)

        total_steps = len(train_loader) * epochs
        warmup_steps = total_steps // 10

        scheduler = get_cosine_schedule_with_warmup(
            optimizer,
            num_warmup_steps=warmup_steps,
            num_training_steps=total_steps
        )

        logger.info(
            f"Optimizer: AdamW | "
            f"Total steps: {total_steps} | "
            f"Warmup: {warmup_steps}"
        )

        # ── 7. Training Loop ───────────────────────────────────
        best_f1 = 0.0
        best_acc = 0.0
        history = []

        for epoch in range(epochs):
            logger.info(f"\n{'='*40}")
            logger.info(f"EPOCH {epoch + 1} / {epochs}")
            logger.info(f"{'='*40}")

            # ── Train Phase ────────────────────────────────────
            model.train()
            train_losses = []
            train_preds = []
            train_labels = []

            for step, batch in enumerate(train_loader):
                iids = batch[0].to(self.device)
                mask = batch[1].to(self.device)
                labs = batch[2].to(self.device)

                optimizer.zero_grad()

                outputs = model(
                    input_ids=iids,
                    attention_mask=mask
                )

                # Use weighted loss
                loss = loss_fn(outputs.logits, labs)
                loss.backward()

                # Gradient clipping
                torch.nn.utils.clip_grad_norm_(
                    model.parameters(), 1.0
                )

                optimizer.step()
                scheduler.step()

                train_losses.append(loss.item())
                preds = torch.argmax(outputs.logits, dim=1)
                train_preds.extend(preds.cpu().tolist())
                train_labels.extend(labs.cpu().tolist())

                if (step + 1) % max(1, len(train_loader) // 3) == 0:
                    current_lr = scheduler.get_last_lr()[0]
                    logger.info(
                        f"  Step {step+1}/{len(train_loader)} | "
                        f"Loss: {loss.item():.4f} | "
                        f"LR: {current_lr:.2e}"
                    )

            avg_train_loss = np.mean(train_losses)
            train_f1 = f1_score(
                train_labels, train_preds,
                average="macro", zero_division=0
            )
            train_acc = accuracy_score(train_labels, train_preds)

            # ── Validation Phase ───────────────────────────────
            model.eval()
            val_losses = []
            val_preds = []
            val_labels_list = []

            with torch.no_grad():
                for batch in val_loader:
                    iids = batch[0].to(self.device)
                    mask = batch[1].to(self.device)
                    labs = batch[2].to(self.device)

                    outputs = model(
                        input_ids=iids,
                        attention_mask=mask
                    )

                    loss = loss_fn(outputs.logits, labs)
                    val_losses.append(loss.item())

                    preds = torch.argmax(outputs.logits, dim=1)
                    val_preds.extend(preds.cpu().tolist())
                    val_labels_list.extend(labs.cpu().tolist())

            avg_val_loss = np.mean(val_losses)
            val_f1 = f1_score(
                val_labels_list, val_preds,
                average="macro", zero_division=0
            )
            val_acc = accuracy_score(val_labels_list, val_preds)

            # ── Log Epoch Results ──────────────────────────────
            logger.info(
                f"\nEpoch {epoch+1} Results:\n"
                f"  Train → Loss: {avg_train_loss:.4f} | "
                f"F1: {train_f1:.4f} | Acc: {train_acc:.4f}\n"
                f"  Val   → Loss: {avg_val_loss:.4f} | "
                f"F1: {val_f1:.4f} | Acc: {val_acc:.4f}"
            )

            # Per-class report
            label_names = [
                id_to_label[i] for i in range(num_labels)
            ]
            report = classification_report(
                val_labels_list, val_preds,
                target_names=label_names,
                zero_division=0,
                digits=3
            )
            logger.info(f"\nValidation Report:\n{report}")

            epoch_data = {
                "epoch": epoch + 1,
                "train_loss": round(float(avg_train_loss), 4),
                "train_f1": round(float(train_f1), 4),
                "train_accuracy": round(float(train_acc), 4),
                "val_loss": round(float(avg_val_loss), 4),
                "val_f1": round(float(val_f1), 4),
                "val_accuracy": round(float(val_acc), 4),
            }
            history.append(epoch_data)

            # ── Save Best Model ────────────────────────────────
            if val_f1 >= best_f1:
                best_f1 = val_f1
                best_acc = val_acc
                self._save_model(model, tokenizer, label_map)
                logger.success(
                    f"✅ New best! "
                    f"F1={best_f1:.4f} | Acc={best_acc:.4f}"
                )

        # ── Save History ───────────────────────────────────────
        history_path = self.model_dir / "history.json"
        with open(history_path, "w") as f:
            json.dump(history, f, indent=2)

        results = {
            "model": self.MODEL_NAME,
            "best_val_f1": round(best_f1, 4),
            "best_val_accuracy": round(best_acc, 4),
            "epochs_trained": epochs,
            "total_samples": len(all_data),
            "num_labels": num_labels,
            "history": history,
            "label_map": label_map
        }

        logger.success(
            f"\n{'='*55}\n"
            f"🎉 Training Complete!\n"
            f"Best Val F1:  {best_f1:.4f}\n"
            f"Best Val Acc: {best_acc:.4f}\n"
            f"{'='*55}"
        )
        return results

    def _save_model(self, model, tokenizer, label_map: dict):
        """Save model artifacts."""
        path = self.model_dir / "cve_classifier"
        path.mkdir(exist_ok=True)
        model.save_pretrained(str(path))
        tokenizer.save_pretrained(str(path))
        with open(path / "label_map.json", "w") as f:
            json.dump(label_map, f, indent=2)
        logger.info(f"Model saved → {path}")

    # Keep _save_classifier as alias for backward compat
    def _save_classifier(self, model):
        pass

    def load_classifier(self) -> tuple:
        """Load trained model from disk."""
        path = self.model_dir / "cve_classifier"
        if not path.exists():
            raise FileNotFoundError(
                f"No model at {path}. Train first."
            )
        with open(path / "label_map.json") as f:
            label_map = json.load(f)
        tokenizer = AutoTokenizer.from_pretrained(str(path))
        model = AutoModelForSequenceClassification.from_pretrained(
            str(path)
        )
        model.to(self.device)
        model.eval()
        logger.info(
            f"Model loaded | {len(label_map)} labels | "
            f"Device: {self.device}"
        )
        return model, tokenizer, label_map

    def predict_exploit_type(
        self,
        text: str,
        model=None,
        tokenizer=None,
        label_map: dict = None
    ) -> dict:
        """Predict CVE exploit type with confidence scores."""
        if model is None:
            model, tokenizer, label_map = self.load_classifier()

        inputs = tokenizer(
            text,
            max_length=128,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        )

        iids = inputs["input_ids"].to(self.device)
        mask = inputs["attention_mask"].to(self.device)

        model.eval()
        with torch.no_grad():
            outputs = model(input_ids=iids, attention_mask=mask)

        probs = torch.softmax(outputs.logits[0], dim=0)
        pred_id = int(torch.argmax(probs).item())
        id2label = {v: k for k, v in label_map.items()}

        # Sort probabilities descending
        sorted_probs = dict(
            sorted(
                {
                    id2label.get(i, f"class_{i}"): round(float(p), 4)
                    for i, p in enumerate(probs)
                }.items(),
                key=lambda x: x[1],
                reverse=True
            )
        )

        return {
            "predicted_label": id2label.get(pred_id, "Unknown"),
            "confidence": round(float(probs[pred_id]), 4),
            "all_probabilities": sorted_probs
        }
