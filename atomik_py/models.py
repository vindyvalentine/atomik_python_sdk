from atomik_py.base import mixin_base_response


@mixin_base_response
class SignerSignResponse:
    tx_hash: str


@mixin_base_response
class SignerVerifyRespons:
    tx_hash: str


@mixin_base_response
class SignerGetFileResponse:
    file: str
    hash: str
    tx_hash: str
    hash_option: str
