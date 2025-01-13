class BaseError(Exception):
    """Base class for all exceptions in this module."""


class AuthError(BaseError):
    """Exception raised for authentication errors."""


class ServerError(BaseError):
    """Exception raised for server-related errors."""


class ServerTimeoutError(ServerError):
    """Exception raised when the server times out."""


class InvalidSignatureError(ServerError):
    """Exception raised for invalid signature errors."""
