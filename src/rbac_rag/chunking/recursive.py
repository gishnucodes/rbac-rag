from __future__ import annotations

from rbac_rag.types import ChunkDraft, SourceDocument

_SEPARATORS = ("\n\n", "\n", ". ", " ")


def split_text(text: str, chunk_size: int, overlap: int) -> list[str]:
    """Split ``text`` into pieces of at most ``chunk_size`` characters,
    preferring paragraph, then line, then sentence, then word boundaries.
    Consecutive pieces share up to ``overlap`` trailing characters."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if not 0 <= overlap < chunk_size:
        raise ValueError("overlap must be in [0, chunk_size)")
    text = text.strip()
    if not text:
        return []
    pieces = _split(text, chunk_size, 0)
    return _merge(pieces, chunk_size, overlap)


def _split(text: str, size: int, depth: int) -> list[str]:
    if len(text) <= size:
        return [text]
    if depth >= len(_SEPARATORS):
        return [text[i : i + size] for i in range(0, len(text), size)]
    sep = _SEPARATORS[depth]
    parts = text.split(sep)
    out: list[str] = []
    for i, part in enumerate(parts):
        piece = part + (sep if i < len(parts) - 1 else "")
        if not piece.strip():
            continue
        out.extend(_split(piece, size, depth + 1) if len(piece) > size else [piece])
    return out


def _merge(pieces: list[str], size: int, overlap: int) -> list[str]:
    chunks: list[str] = []
    current = ""
    for piece in pieces:
        if current and len(current) + len(piece) > size:
            chunks.append(current.strip())
            tail = current[-overlap:] if overlap else ""
            # Start the overlap on a word boundary.
            if tail and " " in tail:
                tail = tail[tail.index(" ") + 1 :]
            current = tail if len(tail) + len(piece) <= size else ""
        current += piece
    if current.strip():
        chunks.append(current.strip())
    return chunks


class RecursiveChunker:
    """Structure-agnostic chunker: the whole document shares one ACL."""

    def __init__(self, chunk_size: int = 800, chunk_overlap: int = 120):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def split(self, document: SourceDocument) -> list[ChunkDraft]:
        return [
            ChunkDraft(content=piece)
            for piece in split_text(document.text, self.chunk_size, self.chunk_overlap)
        ]
