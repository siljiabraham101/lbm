from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .latent import embed, cosine


@dataclass
class Claim:
    claim_hash: str
    text: str
    tags: List[str]
    created_ms: int
    evidence: List[str]
    parent_hash: Optional[str] = None  # For claim threading/conversations
    retracted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "claim_hash": self.claim_hash,
            "text": self.text,
            "tags": list(self.tags),
            "created_ms": int(self.created_ms),
            "evidence": list(self.evidence),
            "retracted": bool(self.retracted),
        }
        if self.parent_hash is not None:
            d["parent_hash"] = self.parent_hash
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Claim":
        return Claim(
            claim_hash=str(d["claim_hash"]),
            text=str(d.get("text", "")),
            tags=list(d.get("tags", [])),
            created_ms=int(d.get("created_ms", 0)),
            evidence=list(d.get("evidence", [])),
            parent_hash=d.get("parent_hash"),  # Optional threading
            retracted=bool(d.get("retracted", False)),
        )


class ContextGraph:
    """Truth-maintenance flavored graph (v1).

    v1 supports:
    - claims (text + tags + evidence references)
    - retractions
    - deterministic compilation via latent-space similarity ranking
    - embedding cache for O(1) retrieval instead of O(n) recomputation
    """

    def __init__(self) -> None:
        self.claims: Dict[str, Claim] = {}
        self._embedding_cache: Dict[str, List[float]] = {}  # claim_hash -> embedding

    def add_claim(
        self,
        claim_hash: str,
        text: str,
        tags: List[str],
        evidence: Optional[List[str]] = None,
        *,
        created_ms: Optional[int] = None,
        parent_hash: Optional[str] = None,
    ) -> None:
        if created_ms is None:
            created_ms = int(time.time() * 1000)
        self.claims[claim_hash] = Claim(
            claim_hash=claim_hash,
            text=text,
            tags=list(tags),
            created_ms=int(created_ms),
            evidence=list(evidence or []),
            parent_hash=parent_hash,
            retracted=False,
        )
        # Pre-compute and cache embedding for O(1) lookup during compile
        self._embedding_cache[claim_hash] = embed(text)

    def retract(self, claim_hash: str) -> None:
        c = self.claims.get(claim_hash)
        if c:
            c.retracted = True
            # Remove from embedding cache to free memory
            self._embedding_cache.pop(claim_hash, None)

    def compile(
        self, query: str, *, top_k: int = 8, since_ms: Optional[int] = None
    ) -> Tuple[str, List[str]]:
        """Compile context slice from claims.

        Args:
            query: Search query for similarity ranking
            top_k: Number of results to return
            since_ms: Only include claims created after this timestamp (optional)

        Returns:
            Tuple of (formatted context string, list of claim hashes)
        """
        qv = embed(query)
        scored: List[Tuple[float, str]] = []
        for h, c in self.claims.items():
            if c.retracted:
                continue
            # Time filter: skip claims older than since_ms
            if since_ms is not None and c.created_ms < since_ms:
                continue
            # Use cached embedding if available, otherwise compute and cache
            if h in self._embedding_cache:
                cv = self._embedding_cache[h]
            else:
                cv = embed(c.text)
                self._embedding_cache[h] = cv
            s = cosine(qv, cv)
            scored.append((s, h))
        scored.sort(key=lambda x: (-x[0], x[1]))
        chosen = [h for _, h in scored[: max(0, int(top_k))]]
        lines = []
        lines.append("Context slice")
        lines.append(f"Query: {query}")
        lines.append("")
        for i, h in enumerate(chosen, 1):
            c = self.claims[h]
            tag_str = (", ".join(c.tags)) if c.tags else ""
            if tag_str:
                lines.append(f"{i}. {c.text}  [tags: {tag_str}]")
            else:
                lines.append(f"{i}. {c.text}")
        return "\n".join(lines).strip() + "\n", chosen

    def snapshot(self) -> Dict[str, Any]:
        return {"claims": {h: c.to_dict() for h, c in self.claims.items()}}

    @staticmethod
    def from_snapshot(s: Dict[str, Any]) -> "ContextGraph":
        g = ContextGraph()
        claims = s.get("claims", {}) or {}
        for h, cd in claims.items():
            claim = Claim.from_dict(cd)
            g.claims[h] = claim
            # Pre-compute embedding for cache
            if not claim.retracted:
                g._embedding_cache[h] = embed(claim.text)
        return g
