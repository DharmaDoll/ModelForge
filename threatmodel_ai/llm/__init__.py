"""Optional LLM helpers."""

from threatmodel_ai.llm.candidates import (
    LLMCandidateModel,
    LLMCandidateValidationError,
    extract_readme_candidates,
    read_llm_candidates,
)
from threatmodel_ai.llm.client import (
    LLMClient,
    LLMConfigurationError,
    LLMRequestError,
    OpenAIResponsesClient,
)
from threatmodel_ai.llm.merge import (
    CandidateMergeError,
    CandidateMergeRejection,
    CandidateMergeResult,
    merge_llm_candidates,
)
from threatmodel_ai.llm.questions import refine_questions

__all__ = [
    "CandidateMergeError",
    "CandidateMergeRejection",
    "CandidateMergeResult",
    "LLMClient",
    "LLMCandidateModel",
    "LLMCandidateValidationError",
    "LLMConfigurationError",
    "LLMRequestError",
    "OpenAIResponsesClient",
    "extract_readme_candidates",
    "merge_llm_candidates",
    "read_llm_candidates",
    "refine_questions",
]
