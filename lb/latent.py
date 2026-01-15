"""
Latent-space retrieval module.

NOTE: Current implementation uses deterministic token hashing for embeddings,
not true semantic embeddings. This provides consistent, reproducible results
but does not capture semantic similarity. For production semantic search,
integrate a real embedding model (e.g., sentence-transformers).

The hash-based approach works by:
1. Tokenizing text into words
2. Hashing each token to a deterministic vector
3. Summing and normalizing the vectors

This enables:
- Deterministic, reproducible results
- No external dependencies
- Fast computation

Limitations:
- No semantic understanding (synonyms won't match)
- Exact token overlap required for similarity
- No context-aware embeddings

To upgrade to semantic embeddings, replace the embed() function with a call
to a real embedding model while maintaining the same interface.
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import List

_WORD_RE = re.compile(r"[A-Za-z0-9_]+")


def _tokenize(text: str) -> List[str]:
    return [t.lower() for t in _WORD_RE.findall(text)]


def embed(text: str, dim: int = 64) -> List[float]:
    toks = _tokenize(text)
    if not toks:
        return [0.0] * dim
    v = [0.0] * dim
    for t in toks:
        h1 = hashlib.sha256(t.encode("utf-8")).digest()
        h2 = hashlib.sha256((t + "\x00").encode("utf-8")).digest()
        b = h1 + h2  # 64 bytes
        for i in range(dim):
            # map byte to [-1, 1]
            v[i] += (b[i] / 127.5) - 1.0
    # normalize
    n = math.sqrt(sum(x * x for x in v))
    if n == 0.0:
        return [0.0] * dim
    return [x / n for x in v]


def cosine(a: List[float], b: List[float]) -> float:
    if len(a) != len(b):
        raise ValueError("dimension mismatch")
    return sum(x * y for x, y in zip(a, b))
