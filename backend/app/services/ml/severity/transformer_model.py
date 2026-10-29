"""
Transformer CVSS Regression - Fixed Version.

Key fixes:
1. Better regression head (no sigmoid bias)
2. Proper score normalization [0,10]
3. Class-weighted sampling for balanced training
4. Better loss function (MSE + severity penalty)
5. Score validation during training
"""

import json
import numpy as np
import torch
import torch.nn as nn
from pathlib import Path
from torch.utils.data import (
    DataLoader, Dataset, WeightedRandomSampler
)
from transformers import (
    AutoModel,
    AutoTokenizer,
    get_cosine_schedule_with_warmup
)
from torch.optim import AdamW
from sklearn.metrics import mean_absolute_error, mean_squared_error
from loguru import logger


class CVSSDataset(Dataset):
    """Dataset for CVSS regression."""

    def __init__(
        self,
        texts: list,
        scores: list,
        tokenizer,
        max_length: int = 128
    ):
        self.encodings = tokenizer(
            texts,
            max_length=max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        )
        # Normalize scores to [0, 1] for stable training
        self.scores = torch.tensor(
            [s / 10.0 for s in scores],
            dtype=torch.float32
        )
        self.raw_scores = scores

    def __len__(self):
        return len(self.scores)

    def __getitem__(self, idx):
        return {
            "input_ids": self.encodings["input_ids"][idx],
            "attention_mask": self.encodings["attention_mask"][idx],
            "score": self.scores[idx],
            "raw_score": self.raw_scores[idx]
        }


class CVSSRegressionModel(nn.Module):
    """
    DistilBERT with proper regression head.

    Fixed architecture:
    - No sigmoid (avoids compression artifacts)
    - Direct linear output scaled to [0, 10]
    - Dropout for regularization
    """

    def __init__(self, model_name: str = "distilbert-base-uncased"):
        super().__init__()
        self.bert = AutoModel.from_pretrained(model_name)
        hidden = self.bert.config.hidden_size  # 768

        # Regression head - no sigmoid to avoid bias
        self.regressor = nn.Sequential(
            nn.Linear(hidden, 256),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, 64),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(64, 1)
        )

        # Initialize weights properly
        for layer in self.regressor:
            if isinstance(layer, nn.Linear):
                nn.init.xavier_normal_(layer.weight)
                nn.init.zeros_(layer.bias)

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor
    ) -> torch.Tensor:
        """
        Forward pass.
        Output: score in [0, 1] range (multiply by 10 for CVSS)
        """
        out = self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask
        )
        # Mean pooling (more stable than CLS token)
        token_embeddings = out.last_hidden_state
        mask_expanded = attention_mask.unsqueeze(-1).float()
        pooled = (
            (token_embeddings * mask_expanded).sum(1) /
            mask_expanded.sum(1).clamp(min=1e-9)
        )

        # Raw output
        raw = self.regressor(pooled).squeeze(-1)

        # Clamp to [0, 1] range (represents CVSS/10)
        return torch.clamp(raw, 0.0, 1.0)


class TransformerSeverityTrainer:
    """
    Fixed CVSS regression trainer.
    """

    MODEL_NAME = "distilbert-base-uncased"

    def __init__(
        self, model_dir: str = "app/models/severity"
    ):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        )
        logger.info(
            f"TransformerSeverityTrainer | "
            f"Device: {self.device}"
        )

    def train(
        self,
        texts: list,
        scores: list,
        epochs: int = 5,
        batch_size: int = 16,
        learning_rate: float = 2e-5,
        max_length: int = 128
    ) -> dict:
        """Train CVSS regression model with fixes."""

        logger.info("=" * 55)
        logger.info("CVSS Transformer Regression Training")
        logger.info(
            f"Samples: {len(texts)} | Epochs: {epochs} | "
            f"LR: {learning_rate}"
        )

        # Score distribution analysis
        score_arr = np.array(scores)
        logger.info(
            f"Score stats: min={score_arr.min():.1f} | "
            f"max={score_arr.max():.1f} | "
            f"mean={score_arr.mean():.2f} | "
            f"std={score_arr.std():.2f}"
        )

        sev_counts = {
            "CRITICAL": int(np.sum(score_arr >= 9.0)),
            "HIGH": int(np.sum((score_arr >= 7.0) & (score_arr < 9.0))),
            "MEDIUM": int(np.sum((score_arr >= 4.0) & (score_arr < 7.0))),
            "LOW": int(np.sum(score_arr < 4.0)),
        }
        logger.info(f"Distribution: {sev_counts}")

        # ── Tokenize ───────────────────────────────────────
        logger.info("Tokenizing...")
        tokenizer = AutoTokenizer.from_pretrained(self.MODEL_NAME)

        # ── Weighted sampling for class balance ───────────
        # LOW severity is rare → oversample it
        weights = []
        for s in scores:
            if s >= 9.0:
                weights.append(1.0)      # CRITICAL
            elif s >= 7.0:
                weights.append(1.2)      # HIGH
            elif s >= 4.0:
                weights.append(1.5)      # MEDIUM
            else:
                weights.append(3.0)      # LOW (rarest - oversample)

        # ── Split ──────────────────────────────────────────
        from sklearn.model_selection import train_test_split
        (tr_texts, val_texts,
         tr_scores, val_scores,
         tr_weights, _) = train_test_split(
            texts, scores, weights,
            test_size=0.15,
            random_state=42
        )

        train_ds = CVSSDataset(
            tr_texts, tr_scores, tokenizer, max_length
        )
        val_ds = CVSSDataset(
            val_texts, val_scores, tokenizer, max_length
        )

        # Weighted sampler for balanced training
        sampler = WeightedRandomSampler(
            weights=tr_weights,
            num_samples=len(tr_weights),
            replacement=True
        )

        train_loader = DataLoader(
            train_ds,
            batch_size=batch_size,
            sampler=sampler
        )
        val_loader = DataLoader(
            val_ds,
            batch_size=batch_size * 2,
            shuffle=False
        )

        logger.info(
            f"Train: {len(train_ds)} | Val: {len(val_ds)}"
        )

        # ── Model ──────────────────────────────────────────
        logger.info("Loading model...")
        model = CVSSRegressionModel(self.MODEL_NAME)
        model.to(self.device)

        params = sum(p.numel() for p in model.parameters())
        logger.info(f"Parameters: {params/1e6:.1f}M")

        # ── Loss: MSE + Severity Category Penalty ─────────
        mse_loss = nn.MSELoss()

        def combined_loss(preds_01, targets_01):
            """
            MSE loss + penalty for wrong severity category.
            preds_01: predictions in [0, 1] (CVSS/10)
            targets_01: targets in [0, 1]
            """
            # Basic MSE
            base_loss = mse_loss(preds_01, targets_01)

            # Severity category penalty
            preds_10 = preds_01 * 10.0
            targets_10 = targets_01 * 10.0

            def to_cat(s):
                return (
                    (s >= 0.9).float() * 3 +
                    ((s >= 0.7) & (s < 0.9)).float() * 2 +
                    ((s >= 0.4) & (s < 0.7)).float() * 1
                )

            pred_cat = to_cat(preds_01)
            true_cat = to_cat(targets_01)
            cat_penalty = ((pred_cat - true_cat) ** 2).mean() * 0.1

            return base_loss + cat_penalty

        # ── Optimizer ──────────────────────────────────────
        optimizer = AdamW(
            model.parameters(),
            lr=learning_rate,
            weight_decay=0.01,
            eps=1e-8
        )
        total_steps = len(train_loader) * epochs
        scheduler = get_cosine_schedule_with_warmup(
            optimizer,
            num_warmup_steps=total_steps // 10,
            num_training_steps=total_steps
        )

        # ── Training ───────────────────────────────────────
        best_mae = float("inf")
        history = []

        for epoch in range(epochs):
            logger.info(f"\n--- Epoch {epoch+1}/{epochs} ---")

            # Train
            model.train()
            tr_losses = []
            tr_preds = []
            tr_true = []

            for batch in train_loader:
                iids = batch["input_ids"].to(self.device)
                mask = batch["attention_mask"].to(self.device)
                targets = batch["score"].to(self.device)

                optimizer.zero_grad()
                preds = model(input_ids=iids, attention_mask=mask)
                loss = combined_loss(preds, targets)
                loss.backward()

                torch.nn.utils.clip_grad_norm_(
                    model.parameters(), 1.0
                )
                optimizer.step()
                scheduler.step()

                tr_losses.append(loss.item())
                # Convert back to CVSS scale [0,10]
                tr_preds.extend(
                    (preds.detach().cpu() * 10).tolist()
                )
                tr_true.extend(
                    (targets.cpu() * 10).tolist()
                )

            # Validate
            model.eval()
            val_preds_list = []
            val_true_list = []

            with torch.no_grad():
                for batch in val_loader:
                    iids = batch["input_ids"].to(self.device)
                    mask = batch["attention_mask"].to(self.device)
                    targets = batch["score"].to(self.device)

                    preds = model(
                        input_ids=iids, attention_mask=mask
                    )
                    val_preds_list.extend(
                        (preds.cpu() * 10).tolist()
                    )
                    val_true_list.extend(
                        (targets.cpu() * 10).tolist()
                    )

            # Metrics
            tr_mae = float(mean_absolute_error(tr_true, tr_preds))
            val_mae = float(
                mean_absolute_error(val_true_list, val_preds_list)
            )
            val_rmse = float(np.sqrt(
                mean_squared_error(val_true_list, val_preds_list)
            ))

            # Severity accuracy
            def to_sev(s):
                if s >= 9.0: return "C"
                if s >= 7.0: return "H"
                if s >= 4.0: return "M"
                return "L"

            sev_acc = float(np.mean([
                to_sev(p) == to_sev(t)
                for p, t in zip(val_preds_list, val_true_list)
            ]))

            avg_train_loss = float(np.mean(tr_losses))

            logger.info(
                f"Train Loss: {avg_train_loss:.4f} | "
                f"Train MAE: {tr_mae:.4f} | "
                f"Val MAE: {val_mae:.4f} | "
                f"Val RMSE: {val_rmse:.4f} | "
                f"Sev Acc: {sev_acc:.4f}"
            )

            # Sample predictions for debugging
            if epoch == epochs - 1:
                samples = list(zip(
                    val_true_list[:5],
                    val_preds_list[:5]
                ))
                logger.info("Sample predictions (true → pred):")
                for t, p in samples:
                    logger.info(
                        f"  {t:.1f} → {p:.1f} "
                        f"({to_sev(t)} → {to_sev(p)})"
                    )

            epoch_data = {
                "epoch": epoch + 1,
                "train_loss": round(avg_train_loss, 4),
                "train_mae": round(tr_mae, 4),
                "val_mae": round(val_mae, 4),
                "val_rmse": round(val_rmse, 4),
                "severity_accuracy": round(sev_acc, 4),
            }
            history.append(epoch_data)

            # Save best
            if val_mae < best_mae:
                best_mae = val_mae
                torch.save(
                    model.state_dict(),
                    self.model_dir / "transformer_regressor.pt"
                )
                tokenizer.save_pretrained(
                    str(self.model_dir / "tokenizer")
                )
                logger.success(
                    f"✅ Best saved! MAE={best_mae:.4f} | "
                    f"SevAcc={sev_acc:.4f}"
                )

        # Save history
        with open(
            self.model_dir / "transformer_history.json", "w"
        ) as f:
            json.dump(history, f, indent=2)

        logger.success(
            f"\nTraining complete! "
            f"Best Val MAE={best_mae:.4f}"
        )

        return {
            "best_val_mae": round(best_mae, 4),
            "best_val_rmse": round(val_rmse, 4),
            "epochs": epochs,
            "history": history
        }

    def load_model(self) -> tuple:
        """Load trained model."""
        model_path = self.model_dir / "transformer_regressor.pt"
        tok_path = self.model_dir / "tokenizer"

        if not model_path.exists():
            raise FileNotFoundError(
                "No trained model. Train first."
            )

        model = CVSSRegressionModel(self.MODEL_NAME)
        model.load_state_dict(
            torch.load(
                model_path,
                map_location=self.device
            )
        )
        model.to(self.device)
        model.eval()

        tokenizer = AutoTokenizer.from_pretrained(str(tok_path))
        logger.info("Transformer regressor loaded")
        return model, tokenizer

    def predict(self, text: str) -> float:
        """
        Predict CVSS score for single text.
        Returns score in [0.0, 10.0] range.
        """
        model, tokenizer = self.load_model()

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
            # Output is in [0, 1] → multiply by 10
            score_01 = model(input_ids=iids, attention_mask=mask)
            score = float(score_01.item()) * 10.0

        # Round to 1 decimal, clamp to valid range
        score = round(float(np.clip(score, 0.1, 10.0)), 1)
        return score
