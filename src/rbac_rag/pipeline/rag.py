"""RAG pipeline for context-augmented generation with access restriction refusals."""

from __future__ import annotations

from rbac_rag.interfaces import LLM
from rbac_rag.pipeline.retriever import SecureRetriever
from rbac_rag.types import Answer, UserContext

REFUSAL = "I don't have access to information that answers this question."

SYSTEM_PROMPT = (
    "You are a helpful assistant. Answer the user's question using ONLY the provided context. "
    f'If the context does not contain enough information to answer the question, reply with exactly: "{REFUSAL}"'
)


class RAGPipeline:
    def __init__(self, retriever: SecureRetriever, llm: LLM):
        self.retriever = retriever
        self.llm = llm

    def answer(self, user: UserContext, question: str) -> Answer:
        retrieval = self.retriever.retrieve(user, question)

        if not retrieval.chunks:
            return Answer(
                question=question,
                text=REFUSAL,
                refused=True,
                retrieval=retrieval,
            )

        context_blocks = "\n\n".join(
            f'<context id="{c.chunk_id}">\n{c.content}\n</context>'
            for c in retrieval.chunks
        )
        prompt = f"{context_blocks}\n\nQuestion: {question}"

        response = self.llm.generate(system=SYSTEM_PROMPT, prompt=prompt).strip()

        if response == REFUSAL:
            refused = True
            text = REFUSAL
        else:
            refused = False
            text = response

        return Answer(
            question=question,
            text=text,
            refused=refused,
            retrieval=retrieval,
        )
