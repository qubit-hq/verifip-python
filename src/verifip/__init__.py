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
from .models import BatchResponse, CheckResponse, HealthResponse, RateLimitInfo

__all__ = [
    "__version__",
    "VerifIPClient",
    "CheckResponse",
    "BatchResponse",
    "HealthResponse",
    "RateLimitInfo",
    "VerifIPError",
    "AuthenticationError",
    "RateLimitError",
    "InvalidRequestError",
    "ServerError",
]
