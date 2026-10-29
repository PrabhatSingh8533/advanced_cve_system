"""CVE NLP Pipeline - Lazy Loading."""
from loguru import logger


class CVENLPPipeline:
    """End-to-end NLP pipeline with lazy initialization."""

    def __init__(self):
        self._cleaner = None
        self._tokenizer = None
        self._ner = None
        self._dep_parser = None
        self._vocab = None
        logger.info("CVENLPPipeline ready (lazy loading)")

    @property
    def cleaner(self):
        if self._cleaner is None:
            from app.services.nlp.text_cleaner import CVETextCleaner
            self._cleaner = CVETextCleaner()
        return self._cleaner

    @property
    def tokenizer(self):
        if self._tokenizer is None:
            from app.services.nlp.tokenizer import CVETokenizer
            self._tokenizer = CVETokenizer()
        return self._tokenizer

    @property
    def ner(self):
        if self._ner is None:
            from app.services.nlp.ner import CVEEntityExtractor
            self._ner = CVEEntityExtractor()
        return self._ner

    @property
    def dep_parser(self):
        if self._dep_parser is None:
            from app.services.nlp.dependency_parser import (
                CVEDependencyParser
            )
            self._dep_parser = CVEDependencyParser()
        return self._dep_parser

    @property
    def vocab(self):
        if self._vocab is None:
            from app.services.nlp.vocabulary import (
                CVEVocabularyBuilder
            )
            self._vocab = CVEVocabularyBuilder()
        return self._vocab

    def process(self, raw_text: str) -> dict:
        """Run full NLP pipeline on CVE description."""
        if not raw_text:
            return {}
        try:
            clean_text = self.cleaner.full_clean(raw_text)
            tokens = self.tokenizer.tokenize(clean_text)
            sentences = self.tokenizer.get_sentences(clean_text)
            pos_tags = self.tokenizer.get_pos_tags(clean_text)
            entities = self.ner.extract_all(clean_text)
            dep_parse = self.dep_parser.parse(clean_text)
            return {
                "original_text": raw_text,
                "clean_text": clean_text,
                "tokens": tokens,
                "token_count": len(tokens),
                "sentences": sentences,
                "pos_tags": pos_tags[:20],
                "entities": entities,
                "dependency_parse": dep_parse,
            }
        except Exception as e:
            logger.error(f"Pipeline error: {e}")
            return {
                "error": str(e),
                "original_text": raw_text,
                "clean_text": "",
                "tokens": [],
                "entities": {}
            }

    def process_batch(self, texts: list) -> list:
        results = []
        for i, text in enumerate(texts):
            results.append(self.process(text))
            if (i + 1) % 10 == 0:
                logger.info(f"Processed {i+1}/{len(texts)}")
        return results

    def build_vocabulary_from_db(self, db) -> dict:
        from app.db.models.cve import CVE
        cves = db.query(CVE.description).all()
        texts = [c.description for c in cves if c.description]
        if not texts:
            return {}
        clean_texts = self.cleaner.batch_clean(texts)
        tokenized = self.tokenizer.process_batch(clean_texts)
        return self.vocab.build_from_corpus(tokenized)
