"""Exception types raised by the keyescrow library."""


class EscrowError(Exception):
    """Base class for all keyescrow errors."""


class AuthenticationError(EscrowError):
    """The supplied passphrase could not unlock the store."""


class StoreExistsError(EscrowError):
    """create() was called for a store file that already exists."""


class StoreNotFoundError(EscrowError):
    """open() was called for a store file that does not exist."""


class KeyNotFoundError(EscrowError):
    """No business key exists for the requested key id."""


class IntegrityError(EscrowError):
    """Ciphertext or wrapped key material failed authentication."""


class RotationStateError(EscrowError):
    """The requested operation conflicts with the rotation state."""


class RequestMismatchError(EscrowError):
    """A rotation request id does not match the persisted request."""
