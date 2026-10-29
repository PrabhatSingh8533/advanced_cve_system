"""CVE Tokenization using SpaCy."""
from loguru import logger


class CVETokenizer:
    """SpaCy-based tokenizer with CVE-specific rules."""

    EXTRA_STOP_WORDS = {
        "allow", "allows", "via", "use", "used", "affect",
        "affects", "affected", "could", "may", "can",
        "vulnerability", "issue", "also"
    }

    def __init__(self, model: str = "en_core_web_sm"):
        self.model_name = model
        self.nlp = self._load_model()
        self._customize()
        logger.info(f"CVETokenizer ready: {model}")

    def _load_model(self):
        """Load SpaCy model - installed via pip wheel."""
        import spacy
        try:
            nlp = spacy.load(self.model_name)
            logger.info(f"SpaCy model loaded: {self.model_name}")
            return nlp
        except OSError as e:
            logger.error(
                f"SpaCy model '{self.model_name}' not found. "
                f"Make sure it is in requirements.txt as a wheel URL. "
                f"Error: {e}"
            )
            raise RuntimeError(
                f"SpaCy model not installed: {self.model_name}"
            ) from e

    def _customize(self):
        """Add CVE-specific stop words."""
        for word in self.EXTRA_STOP_WORDS:
            self.nlp.vocab[word].is_stop = True

    def tokenize(
        self,
        text: str,
        remove_stops: bool = True,
        remove_punct: bool = True,
        lemmatize: bool = True,
        min_length: int = 2
    ) -> list:
        """Tokenize CVE text into clean tokens."""
        if not text:
            return []
        doc = self.nlp(text)
        tokens = []
        for token in doc:
            if token.is_space:
                continue
            if remove_stops and token.is_stop:
                continue
            if remove_punct and token.is_punct:
                continue
            if len(token.text) < min_length:
                continue
            word = token.lemma_ if lemmatize else token.text
            if not (word.startswith("CVE-") or
                    word.startswith("CWE-")):
                word = word.lower()
            tokens.append(word)
        return tokens

    def get_sentences(self, text: str) -> list:
        """Split text into sentences."""
        if not text:
            return []
        return [s.text.strip() for s in self.nlp(text).sents]

    def get_pos_tags(self, text: str) -> list:
        """Get POS tags."""
        if not text:
            return []
        return [
            (t.text, t.pos_)
            for t in self.nlp(text)
            if not t.is_space
        ]

    def process_batch(
        self, texts: list, batch_size: int = 32
    ) -> list:
        """Process multiple texts efficiently."""
        results = []
        for doc in self.nlp.pipe(texts, batch_size=batch_size):
            results.append([
                t.lemma_.lower() for t in doc
                if not t.is_space and not t.is_stop
                and not t.is_punct and len(t.text) >= 2
            ])
        return results
