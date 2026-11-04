"""F19: similar past cases, TF-IDF by default. The query is code-derived, never raw alert text."""
from __future__ import annotations

import json
import logging

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors

from alertlens.config import ROOT, get_settings
from alertlens.mitre.mapper import RULE_CATALOGUE
from alertlens.schemas import Alert

log = logging.getLogger(__name__)


class Retriever:
    def __init__(self, cases: list[dict]):
        self.cases = cases
        self.embedder = None
        texts = [f"{c['summary']} {c['resolution']} {' '.join(c.get('techniques', []))}" for c in cases]
        if get_settings().embeddings == "minilm":
            try:
                from sentence_transformers import SentenceTransformer  # optional, see requirements-extra.txt

                self.embedder = SentenceTransformer("all-MiniLM-L6-v2")
                matrix = self.embedder.encode(texts)
            except ImportError:
                log.warning("sentence-transformers is not installed, using TF-IDF")
        if self.embedder is None:
            self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
            matrix = self.vectorizer.fit_transform(texts)
        self.nn = NearestNeighbors(metric="cosine").fit(matrix)

    def query(self, text: str, k: int = 3) -> list[dict]:
        vec = self.embedder.encode([text]) if self.embedder else self.vectorizer.transform([text])
        dist, idx = self.nn.kneighbors(vec, n_neighbors=min(k, len(self.cases)))
        return [{**self.cases[int(i)], "similarity": round(float(1 - d), 3)}
                for d, i in zip(np.ravel(dist), np.ravel(idx), strict=True)]


def query_text(alert: Alert, mitre: list[dict]) -> str:
    entry = RULE_CATALOGUE.get(alert.rule_id, {})
    return " ".join([entry.get("title", alert.category), alert.category, *[t["name"] for t in mitre], *[t["id"] for t in mitre]])


def load_cases() -> list[dict]:
    path = ROOT / "data" / "benchmark" / "resolved_cases.jsonl"
    if path.exists():
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    from data.generator.generate import resolved_cases

    return resolved_cases(get_settings().seed)


_retriever: Retriever | None = None


def get_retriever() -> Retriever:
    global _retriever
    if _retriever is None:
        _retriever = Retriever(load_cases())
    return _retriever


def similar_cases(alert: Alert, mitre: list[dict], k: int = 3) -> list[dict]:
    return get_retriever().query(query_text(alert, mitre), k)
