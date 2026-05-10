"""VerifIP - Official Python SDK for the VerifIP IP fraud scoring API."""

from ._version import __version__
from .client import VerifIPClient
from .exceptions import (
    AuthenticationError,
    InvalidRequestError,
    RateLimitError,
    ServerError,
    VerifIPError,
)
from .models import (
    AssessResponse,
    BatchResponse,
    CheckResponse,
    EmailResponse,
    HealthResponse,
    PhoneResponse,
    RateLimitInfo,
    ReportResponse,
    URLResponse,
    WHOISResponse,
)

__all__ = [
    "__version__",
    "VerifIPClient",
    "CheckResponse",
    "BatchResponse",
    "HealthResponse",
    "RateLimitInfo",
    "EmailResponse",
    "PhoneResponse",
    "URLResponse",
    "WHOISResponse",
    "ReportResponse",
    "AssessResponse",
    "VerifIPError",
    "AuthenticationError",
    "RateLimitError",
    "InvalidRequestError",
    "ServerError",
]
