"""CVE Vocabulary Builder."""
import json
from collections import Counter
from pathlib import Path
from loguru import logger


class CVEVocabularyBuilder:
    """Builds domain-specific vocabulary from CVE corpus."""

    SPECIAL_TOKENS = {
        "<PAD>": 0, "<UNK>": 1, "<CVE>": 2,
        "<CWE>": 3, "[VERSION]": 4,
        "[URL]": 5, "[IP]": 6
    }

    def __init__(
        self,
        vocab_path: str = "app/data/cve_vocabulary.json"
    ):
        self.vocab_path = Path(vocab_path)
        self.vocab_path.parent.mkdir(parents=True, exist_ok=True)
        self.vocabulary = {}
        self.word_freq = Counter()
        if self.vocab_path.exists():
            self.load()

    def build_from_corpus(
        self, tokenized_docs: list, min_freq: int = 2
    ) -> dict:
        for tokens in tokenized_docs:
            self.word_freq.update(tokens)
        self.vocabulary = dict(self.SPECIAL_TOKENS)
        idx = len(self.vocabulary)
        for term, freq in self.word_freq.most_common():
            if freq < min_freq:
                break
            if term not in self.vocabulary:
                self.vocabulary[term] = idx
                idx += 1
        logger.success(f"Vocabulary size: {len(self.vocabulary)}")
        self.save()
        return self.vocabulary

    def encode(self, tokens: list) -> list:
        unk = self.SPECIAL_TOKENS["<UNK>"]
        return [self.vocabulary.get(t, unk) for t in tokens]

    def save(self):
        with open(self.vocab_path, "w") as f:
            json.dump({
                "vocabulary": self.vocabulary,
                "word_freq": dict(
                    self.word_freq.most_common(5000)
                )
            }, f, indent=2)

    def load(self):
        with open(self.vocab_path) as f:
            data = json.load(f)
        self.vocabulary = data.get("vocabulary", {})
        self.word_freq = Counter(data.get("word_freq", {}))
        logger.info(f"Vocabulary loaded: {len(self.vocabulary)}")
