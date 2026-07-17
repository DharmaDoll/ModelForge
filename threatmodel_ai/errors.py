"""User-facing exceptions for deterministic analysis failures."""

from __future__ import annotations


class ModelForgeError(Exception):
    """Base exception for errors that should be shown clearly in the CLI."""

    def __init__(
        self,
        message: str,
        *,
        detail: str | None = None,
        hint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail
        self.hint = hint


class InputFormatError(ModelForgeError):
    """Raised when an input file is present but not parseable for its declared type."""


class AnalysisInputError(ModelForgeError):
    """Raised when analysis cannot start because supported inputs are missing."""
