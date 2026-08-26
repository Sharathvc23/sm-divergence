"""Declared divergence — advance declarations a source publishes about its own
variation, and the verification that makes them worth anything."""

from .answer_scope import (
    ANSWER_SCOPE_VERSION,
    MAX_SCOPES,
    OCCUPIABLE_CLASSES,
    AnswerScope,
    build_answer_scope,
    verify_answer_scope,
)

__all__ = [
    "ANSWER_SCOPE_VERSION",
    "MAX_SCOPES",
    "OCCUPIABLE_CLASSES",
    "AnswerScope",
    "build_answer_scope",
    "verify_answer_scope",
]
