"""Dependency Parsing for CVE text."""
from loguru import logger


class CVEDependencyParser:
    """Parses syntactic dependencies in CVE descriptions."""

    def __init__(self, model: str = "en_core_web_sm"):
        """Load SpaCy model installed via pip wheel."""
        import spacy
        try:
            self.nlp = spacy.load(model)
            logger.info(f"Parser SpaCy model loaded: {model}")
        except OSError as e:
            logger.error(f"SpaCy model not found: {e}")
            raise RuntimeError(f"SpaCy model not installed: {model}")

    def extract_triples(self, text: str) -> list:
        """Extract Subject-Verb-Object triples."""
        if not text:
            return []
        doc = self.nlp(text)
        triples = []
        for sent in doc.sents:
            for token in sent:
                if token.pos_ == "VERB":
                    subj = next(
                        (c.text for c in token.children
                         if c.dep_ in ("nsubj", "nsubjpass")), ""
                    )
                    obj = next(
                        (c.text for c in token.children
                         if c.dep_ in ("dobj", "pobj", "attr")), ""
                    )
                    if subj and obj:
                        triples.append({
                            "subject": subj,
                            "verb": token.lemma_,
                            "object": obj
                        })
        return triples

    def get_key_phrases(self, text: str) -> list:
        """Extract key noun phrases."""
        if not text:
            return []
        doc = self.nlp(text)
        seen = set()
        phrases = []
        for chunk in doc.noun_chunks:
            phrase = chunk.text.strip()
            if phrase.lower() not in seen and len(phrase) > 3:
                seen.add(phrase.lower())
                phrases.append(phrase)
        return phrases[:10]

    def parse(self, text: str) -> dict:
        """Full dependency parse."""
        return {
            "triples": self.extract_triples(text),
            "key_phrases": self.get_key_phrases(text)
        }
