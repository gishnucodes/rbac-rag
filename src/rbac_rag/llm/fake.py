from __future__ import annotations

import re

from rbac_rag.embeddings.fake import _tokens

_CONTEXT_RE = re.compile(r"<context id=\"[^\"]*\">\n(.*?)\n</context>", re.DOTALL)
_QUESTION_RE = re.compile(r"Question:\s*(.*)\s*$", re.DOTALL)
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+|\n+")


class ExtractiveLLM:
    """Offline stand-in for an LLM: answers with the context sentences that
    best overlap the question, or the refusal sentence when there is no
    context. Only understands prompts built by :class:`rbac_rag.pipeline.rag.RAGPipeline`."""

    def __init__(self, refusal: str | None = None, max_sentences: int = 2):
        from rbac_rag.pipeline.rag import REFUSAL

        self.refusal = refusal or REFUSAL
        self.max_sentences = max_sentences

    def generate(self, system: str, prompt: str) -> str:
        contexts = _CONTEXT_RE.findall(prompt)
        question_match = _QUESTION_RE.search(prompt)
        if not contexts or not question_match:
            return self.refusal
        query = set(_tokens(question_match.group(1)))
        scored = []
        for context in contexts:
            # Drop the breadcrumb line added by the markdown chunker.
            body = context.split("\n", 1)[-1]
            for sentence in _SENTENCE_RE.split(body):
                sentence = sentence.strip(" -*#")
                if len(sentence) < 12:
                    continue
                overlap = len(query & set(_tokens(sentence)))
                if overlap:
                    scored.append((overlap, sentence))
        if not scored:
            return self.refusal
        scored.sort(key=lambda s: -s[0])
        return " ".join(s for _, s in scored[: self.max_sentences])
