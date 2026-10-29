"""
PyTorch Dataset classes for BERT fine-tuning.

Handles tokenization and encoding of CVE text
for both classification and NER tasks.
"""

import torch
from torch.utils.data import Dataset
from transformers import AutoTokenizer
from loguru import logger


class CVEClassificationDataset(Dataset):
    """
    PyTorch Dataset for CVE exploit type classification.

    Encodes text using BERT tokenizer with:
    - Max length truncation
    - Attention masks
    - Token type IDs
    """

    def __init__(
        self,
        data: list[dict],
        tokenizer_name: str = "bert-base-uncased",
        max_length: int = 256
    ):
        """
        Initialize classification dataset.

        Args:
            data: List of {text, label_id} dicts
            tokenizer_name: HuggingFace tokenizer name
            max_length: Maximum token sequence length
        """
        self.data = data
        self.max_length = max_length

        # Load tokenizer
        logger.info(f"Loading tokenizer: {tokenizer_name}")
        self.tokenizer = AutoTokenizer.from_pretrained(tokenizer_name)

        logger.info(
            f"Classification dataset ready: {len(data)} samples"
        )

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, idx: int) -> dict:
        """
        Get a single encoded sample.

        Returns:
            Dict with input_ids, attention_mask, labels tensors
        """
        item = self.data[idx]
        text = item["text"]
        label = item["label_id"]

        # Tokenize text
        encoding = self.tokenizer(
            text,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        )

        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "labels": torch.tensor(label, dtype=torch.long)
        }


class CVENERDataset(Dataset):
    """
    PyTorch Dataset for CVE Named Entity Recognition.

    Handles BIO-tagged sequences for token classification.
    """

    # BIO tag to ID mapping
    TAG2ID = {
        "O": 0,
        "B-CVE": 1, "I-CVE": 2,
        "B-CWE": 3, "I-CWE": 4,
        "B-EXPLOIT": 5, "I-EXPLOIT": 6,
    }

    ID2TAG = {v: k for k, v in TAG2ID.items()}

    def __init__(
        self,
        data: list[dict],
        tokenizer_name: str = "bert-base-uncased",
        max_length: int = 256
    ):
        """
        Initialize NER dataset.

        Args:
            data: List of {tokens, ner_tags} dicts
            tokenizer_name: HuggingFace tokenizer name
            max_length: Maximum sequence length
        """
        self.data = data
        self.max_length = max_length
        self.tokenizer = AutoTokenizer.from_pretrained(tokenizer_name)
        logger.info(f"NER dataset ready: {len(data)} samples")

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, idx: int) -> dict:
        """
        Get single NER sample with aligned labels.

        Handles WordPiece tokenization alignment:
        - Original: ["Apache", "Log4j2"]
        - WordPiece: ["Apache", "Log", "##4", "##j", "##2"]
        - Labels aligned with -100 for sub-tokens
        """
        item = self.data[idx]
        words = item["tokens"]
        tags = item["ner_tags"]

        # Tokenize with word IDs for alignment
        encoding = self.tokenizer(
            words,
            is_split_into_words=True,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        )

        # Align labels with sub-tokens
        word_ids = encoding.word_ids()
        aligned_labels = []
        prev_word_id = None

        for word_id in word_ids:
            if word_id is None:
                # Special tokens ([CLS], [SEP], [PAD]) → -100
                aligned_labels.append(-100)
            elif word_id != prev_word_id:
                # First token of each word → use real label
                tag = tags[word_id] if word_id < len(tags) else "O"
                aligned_labels.append(self.TAG2ID.get(tag, 0))
            else:
                # Sub-word tokens → -100 (ignored in loss)
                aligned_labels.append(-100)

            prev_word_id = word_id

        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "labels": torch.tensor(aligned_labels, dtype=torch.long)
        }