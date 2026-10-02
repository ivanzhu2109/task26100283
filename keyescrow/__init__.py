"""AES-256 business key escrow library backed by SQLite."""

from .errors import (
    AuthenticationError,
    EscrowError,
    IntegrityError,
    KeyNotFoundError,
    RequestMismatchError,
    RotationStateError,
    StoreExistsError,
    StoreNotFoundError,
)
from .store import EscrowStore, RotationStatus

__all__ = [
    "EscrowStore",
    "RotationStatus",
    "EscrowError",
    "AuthenticationError",
    "IntegrityError",
    "KeyNotFoundError",
    "RequestMismatchError",
    "RotationStateError",
    "StoreExistsError",
    "StoreNotFoundError",
]
