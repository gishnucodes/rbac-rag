"""Unit tests for evals/ragas_eval.py metric wiring, embedding adapter, and credential skip."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evals.ragas_eval import (
    GeminiRagasEmbeddingAdapter,
    canaries_for_persona,
    check_google_credentials,
    compute_unauthorized_canaries_by_persona,
    evaluate_sample,
)
from rbac_rag.config import Settings
from rbac_rag.pipeline.rag import REFUSAL
from rbac_rag.types import Acl, Answer, RetrievedChunk, RetrievalResult, UserContext


class StubEmbedder:
    def embed_text(self, text: str) -> list[float]:
        return [0.1, 0.2, 0.3]

    async def aembed_text(self, text: str) -> list[float]:
        return [0.1, 0.2, 0.3]


def test_gemini_ragas_embedding_adapter():
    embedder = StubEmbedder()
    adapter = GeminiRagasEmbeddingAdapter(embedder)

    sync_res = adapter.embed_text("test query")
    assert sync_res == [0.1, 0.2, 0.3]

    async_res = asyncio.run(adapter.aembed_text("test query"))
    assert async_res == [0.1, 0.2, 0.3]


def test_check_google_credentials():
    settings_no_creds = Settings(
        google_api_key=None,
        google_cloud_project=None,
    )
    with patch.dict("os.environ", {}, clear=True):
        assert not check_google_credentials(settings_no_creds)

    settings_with_key = Settings(google_api_key="test-key")
    assert check_google_credentials(settings_with_key)


def test_evaluate_sample_wiring_answerable():
    sample = {
        "id": "test_sample_1",
        "persona": "alice",
        "question": "What is Q3 revenue?",
        "should_refuse": False,
        "reference": "Q3 revenue was $48.2M.",
        "forbidden_canaries": ["NIGHTJAR-7731"],
        "sensitive_facts": "Q3 revenue $48.2M.",
    }

    dummy_chunk = RetrievedChunk(
        chunk_id="c1",
        document_id="doc1",
        title="Finance Q3",
        content="Consolidated Q3 revenue reached $48.2M.",
        classification="internal",
        score=0.9,
        acl=Acl(),
    )
    dummy_retrieval = RetrievalResult(
        user=UserContext(user_id="alice", policy_version=1),
        policy_version=1,
        query="What is Q3 revenue?",
        chunks=[dummy_chunk],
    )
    dummy_answer = Answer(
        question="What is Q3 revenue?",
        text="Consolidated Q3 revenue reached $48.2M.",
        refused=False,
        retrieval=dummy_retrieval,
    )

    mock_rag_pipeline = MagicMock()
    mock_rag_pipeline.answer.return_value = dummy_answer

    mock_llm = MagicMock()

    # Mock DiscreteMetric and RAGAS metric ascore
    mock_metric_res = MagicMock()
    mock_metric_res.value = "safe"

    mock_ragas_score = MagicMock()
    mock_ragas_score.value = 0.95

    mock_adapter = MagicMock()
    semaphore = asyncio.Semaphore(1)

    with (
        patch("evals.ragas_eval.DiscreteMetric") as mock_discrete,
        patch("evals.ragas_eval.Faithfulness") as mock_f,
        patch("evals.ragas_eval.AnswerRelevancy") as mock_ar,
        patch("evals.ragas_eval.ContextPrecisionWithReference") as mock_cp,
        patch("evals.ragas_eval.ContextRecall") as mock_cr,
    ):
        mock_discrete.return_value.ascore = AsyncMock(return_value=mock_metric_res)
        mock_f.return_value.ascore = AsyncMock(return_value=mock_ragas_score)
        mock_ar.return_value.ascore = AsyncMock(return_value=mock_ragas_score)
        mock_cp.return_value.ascore = AsyncMock(return_value=mock_ragas_score)
        mock_cr.return_value.ascore = AsyncMock(return_value=mock_ragas_score)

        res = asyncio.run(
            evaluate_sample(
                sample=sample,
                policy_version=1,
                settings=Settings(),
                llm=mock_llm,
                ragas_embeddings=mock_adapter,
                semaphore=semaphore,
                rag_pipeline=mock_rag_pipeline,
                unauthorized_canaries={"NIGHTJAR-7731"},
            )
        )

        assert res["id"] == "test_sample_1"
        assert res["persona"] == "alice"
        assert not res["refused"]
        assert res["refusal_correctness"]
        assert res["canary_safe"]
        assert res["leakage_critic"] == "safe"
        assert res["faithfulness"] == 0.95
        assert res["answer_relevancy"] == 0.95
        assert res["context_precision"] == 0.95
        assert res["context_recall"] == 0.95


def test_evaluate_sample_wiring_refusal():
    sample = {
        "id": "test_sample_refuse",
        "persona": "dave",
        "question": "What is the L5 base salary?",
        "should_refuse": True,
        "reference": REFUSAL,
        "forbidden_canaries": ["COMPBAND-9921"],
        "sensitive_facts": "L5 base salary $187,400.",
    }

    dummy_retrieval = RetrievalResult(
        user=UserContext(user_id="dave", policy_version=1),
        policy_version=1,
        query="What is the L5 base salary?",
        chunks=[],
    )
    dummy_answer = Answer(
        question="What is the L5 base salary?",
        text=REFUSAL,
        refused=True,
        retrieval=dummy_retrieval,
    )

    mock_rag_pipeline = MagicMock()
    mock_rag_pipeline.answer.return_value = dummy_answer

    mock_llm = MagicMock()
    mock_metric_res = MagicMock()
    mock_metric_res.value = "safe"

    mock_adapter = MagicMock()
    semaphore = asyncio.Semaphore(1)

    with patch("evals.ragas_eval.DiscreteMetric") as mock_discrete:
        mock_discrete.return_value.ascore = AsyncMock(return_value=mock_metric_res)

        res = asyncio.run(
            evaluate_sample(
                sample=sample,
                policy_version=1,
                settings=Settings(),
                llm=mock_llm,
                ragas_embeddings=mock_adapter,
                semaphore=semaphore,
                rag_pipeline=mock_rag_pipeline,
                unauthorized_canaries={"COMPBAND-9921"},
            )
        )

        assert res["id"] == "test_sample_refuse"
        assert res["refused"]
        assert res["refusal_correctness"]
        assert res["canary_safe"]
        assert res["leakage_critic"] == "safe"
        # RAGAS metrics should remain None for refused rows
        assert res["faithfulness"] is None
        assert res["answer_relevancy"] is None


def test_evaluate_sample_unauthorized_canary_in_non_refusal():
    sample = {
        "id": "sample_unauth_canary",
        "persona": "alice",
        "question": "Tell me a secret",
        "should_refuse": False,
        "reference": "Some info",
        "sensitive_facts": "",
    }
    dummy_answer = Answer(
        question="Tell me a secret",
        text="Here is the canary FINQ3-5582 in text",
        refused=False,
        retrieval=RetrievalResult(
            user=UserContext(user_id="alice", policy_version=1),
            policy_version=1,
            query="Tell me a secret",
            chunks=[],
        ),
    )
    mock_rag_pipeline = MagicMock()
    mock_rag_pipeline.answer.return_value = dummy_answer
    mock_llm = MagicMock()
    mock_metric_res = MagicMock(value="safe")

    with patch("evals.ragas_eval.DiscreteMetric") as mock_discrete:
        mock_discrete.return_value.ascore = AsyncMock(return_value=mock_metric_res)
        res = asyncio.run(
            evaluate_sample(
                sample=sample,
                policy_version=1,
                settings=Settings(),
                llm=mock_llm,
                ragas_embeddings=MagicMock(),
                semaphore=asyncio.Semaphore(1),
                rag_pipeline=mock_rag_pipeline,
                unauthorized_canaries={"FINQ3-5582"},
            )
        )
        assert res["canary_safe"] is False
        assert "FINQ3-5582" in res["leaked_canaries"]


def test_evaluate_sample_authorized_canary_in_non_refusal():
    sample = {
        "id": "sample_auth_canary",
        "persona": "alice",
        "question": "Tell me a secret",
        "should_refuse": False,
        "reference": "Some info",
        "sensitive_facts": "",
    }
    dummy_answer = Answer(
        question="Tell me a secret",
        text="Here is the canary FINQ3-5582 in text",
        refused=False,
        retrieval=RetrievalResult(
            user=UserContext(user_id="alice", policy_version=1),
            policy_version=1,
            query="Tell me a secret",
            chunks=[],
        ),
    )
    mock_rag_pipeline = MagicMock()
    mock_rag_pipeline.answer.return_value = dummy_answer
    mock_llm = MagicMock()
    mock_metric_res = MagicMock(value="safe")

    with patch("evals.ragas_eval.DiscreteMetric") as mock_discrete:
        mock_discrete.return_value.ascore = AsyncMock(return_value=mock_metric_res)
        res = asyncio.run(
            evaluate_sample(
                sample=sample,
                policy_version=1,
                settings=Settings(),
                llm=mock_llm,
                ragas_embeddings=MagicMock(),
                semaphore=asyncio.Semaphore(1),
                rag_pipeline=mock_rag_pipeline,
                unauthorized_canaries={"NIGHTJAR-7731"},
            )
        )
        assert res["canary_safe"] is True
        assert res["leaked_canaries"] == []


def test_canaries_for_persona():
    unauthorized_map = {"alice": {"FINQ3-5582"}}
    all_canaries = {"FINQ3-5582", "NIGHTJAR-7731"}

    assert canaries_for_persona("alice", unauthorized_map, all_canaries) == {"FINQ3-5582"}
    assert canaries_for_persona("unknown_user", unauthorized_map, all_canaries) == {"FINQ3-5582", "NIGHTJAR-7731"}


def test_evaluate_sample_persona_missing_from_map():
    sample = {
        "id": "sample_unknown_persona",
        "persona": "unknown_user",
        "question": "Tell me something",
        "should_refuse": False,
        "reference": "Some info",
        "sensitive_facts": "",
    }
    dummy_answer = Answer(
        question="Tell me something",
        text="Here is FINQ3-5582",
        refused=False,
        retrieval=RetrievalResult(
            user=UserContext(user_id="unknown_user", policy_version=1),
            policy_version=1,
            query="Tell me something",
            chunks=[],
        ),
    )
    mock_rag_pipeline = MagicMock()
    mock_rag_pipeline.answer.return_value = dummy_answer
    mock_llm = MagicMock()
    mock_metric_res = MagicMock(value="safe")

    fake_unauthorized_map = {"alice": {"NIGHTJAR-7731"}}
    fake_all_canaries = {"FINQ3-5582", "NIGHTJAR-7731"}

    with (
        patch("evals.ragas_eval.DiscreteMetric") as mock_discrete,
        patch(
            "evals.ragas_eval.compute_unauthorized_canaries_by_persona",
            return_value=(fake_unauthorized_map, fake_all_canaries),
        ),
    ):
        mock_discrete.return_value.ascore = AsyncMock(return_value=mock_metric_res)
        res = asyncio.run(
            evaluate_sample(
                sample=sample,
                policy_version=1,
                settings=Settings(),
                llm=mock_llm,
                ragas_embeddings=MagicMock(),
                semaphore=asyncio.Semaphore(1),
                rag_pipeline=mock_rag_pipeline,
                unauthorized_canaries=None,
            )
        )
        assert res["canary_safe"] is False
        assert "FINQ3-5582" in res["leaked_canaries"]


def test_compute_unauthorized_canaries_by_persona_raises():
    with pytest.raises(RuntimeError):
        compute_unauthorized_canaries_by_persona(
            policy_version=999,
            settings=Settings(database_url="postgresql://invalid:invalid@localhost:5432/invalid"),
        )
