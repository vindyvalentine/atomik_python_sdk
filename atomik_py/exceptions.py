class BaseError(Exception):
    pass


class AuthError(BaseError):
    pass


class ServerError(BaseError):
    pass


class ServerTimeoutError(ServerError):
    pass


class InvalidSignatureError(ServerError):
    pass
