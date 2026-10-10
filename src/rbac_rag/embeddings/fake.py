from __future__ import annotations

import hashlib
import math
import re

_TOKEN_RE = re.compile(r"[a-z0-9$][a-z0-9$.,\-]*[a-z0-9]|[a-z0-9]")
_STOPWORDS = frozenset(
    "a an and are as at be by can do does for from has have how i in is it its me my of on or "
    "our should the their there this to was we what when where which who why will with you".split()
)


def _tokens(text: str) -> list[str]:
    words = [w for w in _TOKEN_RE.findall(text.lower()) if w not in _STOPWORDS]
    # Light stemming so "salaries"/"salary" and "deploys"/"deploy" collide.
    stems = [w[:-3] + "y" if w.endswith("ies") else w[:-1] if w.endswith("s") else w for w in words]
    return stems + [f"{a}_{b}" for a, b in zip(stems, stems[1:])]


class HashingEmbedder:
    """Deterministic, offline bag-of-words embedder (signed feature hashing).

    It captures lexical overlap only, which is enough to exercise retrieval
    and the ACL filter in tests and demos without network access.
    """

    def __init__(self, dim: int = 768):
        self.dim = dim

    def _embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for token in _tokens(text):
            digest = hashlib.blake2b(token.encode(), digest_size=8).digest()
            index = int.from_bytes(digest[:4], "little") % self.dim
            vec[index] += 1.0 if digest[4] & 1 else -1.0
        norm = math.sqrt(sum(v * v for v in vec))
        if norm == 0:
            # pgvector cosine distance is undefined for the zero vector.
            vec[0] = 1.0
            return vec
        return [v / norm for v in vec]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)
