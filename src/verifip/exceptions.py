"""VerifIP SDK exceptions."""

from __future__ import annotations


class VerifIPError(Exception):
    """Base exception for all VerifIP API errors."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 0,
        error_code: str = "",
        retry_after: int | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.retry_after = retry_after

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.status_code}, {self.error_code!r}, {str(self)!r})"


class AuthenticationError(VerifIPError):
    """Raised on 401 (invalid API key) or 403 (key disabled)."""


class RateLimitError(VerifIPError):
    """Raised on 429 (rate limit exceeded). Check retry_after for wait time."""


class InvalidRequestError(VerifIPError):
    """Raised on 400 (invalid IP, bad request body)."""


class ServerError(VerifIPError):
    """Raised on 5xx server errors."""
