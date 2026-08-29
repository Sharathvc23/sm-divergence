"""Declared divergence — advance declarations a source publishes about its own
variation, and the verification that makes them worth anything."""

from .answer_scope import (
    ANSWER_SCOPE_VERSION,
    MAX_SCOPES,
    OCCUPIABLE_CLASSES,
    AnswerScope,
    build_answer_scope,
    scope_evidence,
    verify_answer_scope,
)
from .history import verify_history_proof

__all__ = [
    "ANSWER_SCOPE_VERSION",
    "MAX_SCOPES",
    "OCCUPIABLE_CLASSES",
    "AnswerScope",
    "build_answer_scope",
    "scope_evidence",
    "verify_history_proof",
    "verify_answer_scope",
]
