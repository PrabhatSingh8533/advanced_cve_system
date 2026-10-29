"""
BERT Model Definitions for CVE Analysis Tasks.

Task 1: Exploit Type Classification (9 classes)
Task 2: Named Entity Recognition (BIO tagging)
"""

import torch
import torch.nn as nn
from transformers import (
    BertModel,
    BertPreTrainedModel,
    BertConfig,
)
from loguru import logger


class BERTCVEClassifier(BertPreTrainedModel):
    """
    BERT-based CVE Exploit Type Classifier.

    Architecture:
    BERT → [CLS] token → Dropout → Linear → Softmax → Class Label

    Fine-tuned for 9 exploit type categories.
    """

    def __init__(self, config: BertConfig, num_labels: int = 9):
        super().__init__(config)
        self.num_labels = num_labels

        # BERT backbone
        self.bert = BertModel(config)

        # Classification head
        self.dropout = nn.Dropout(config.hidden_dropout_prob)
        self.classifier = nn.Linear(config.hidden_size, num_labels)

        # Initialize weights
        self.init_weights()

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        token_type_ids: torch.Tensor = None,
        labels: torch.Tensor = None
    ) -> dict:
        """
        Forward pass.

        Args:
            input_ids: Token IDs [batch, seq_len]
            attention_mask: Attention mask [batch, seq_len]
            token_type_ids: Segment IDs [batch, seq_len]
            labels: Ground truth labels [batch] (optional)

        Returns:
            Dict with loss (if labels given) and logits
        """
        # Get BERT outputs
        outputs = self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids
        )

        # Use [CLS] token representation
        pooled_output = outputs.pooler_output

        # Apply dropout
        pooled_output = self.dropout(pooled_output)

        # Classification layer
        logits = self.classifier(pooled_output)

        result = {"logits": logits}

        # Calculate loss if labels provided
        if labels is not None:
            loss_fn = nn.CrossEntropyLoss()
            result["loss"] = loss_fn(logits, labels)

        return result


class BERTCVEEntityExtractor(BertPreTrainedModel):
    """
    BERT-based CVE Named Entity Recognizer.

    Architecture:
    BERT → Token Embeddings → Dropout → Linear → BIO Tags

    Tags: O, B-CVE, I-CVE, B-CWE, I-CWE, B-EXPLOIT, I-EXPLOIT
    """

    NUM_TAGS = 7  # BIO tag count

    def __init__(self, config: BertConfig):
        super().__init__(config)
        self.num_labels = self.NUM_TAGS

        # BERT backbone
        self.bert = BertModel(config)

        # NER head (per-token classification)
        self.dropout = nn.Dropout(config.hidden_dropout_prob)
        self.classifier = nn.Linear(config.hidden_size, self.NUM_TAGS)

        self.init_weights()

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        token_type_ids: torch.Tensor = None,
        labels: torch.Tensor = None
    ) -> dict:
        """
        Forward pass for token classification.

        Returns:
            Dict with loss (if labels given) and logits per token
        """
        outputs = self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids
        )

        # Get all token embeddings (not just [CLS])
        sequence_output = outputs.last_hidden_state

        # Apply dropout
        sequence_output = self.dropout(sequence_output)

        # Per-token classification
        logits = self.classifier(sequence_output)

        result = {"logits": logits}

        if labels is not None:
            loss_fn = nn.CrossEntropyLoss(ignore_index=-100)
            # Reshape for loss calculation
            loss = loss_fn(
                logits.view(-1, self.NUM_TAGS),
                labels.view(-1)
            )
            result["loss"] = loss

        return result