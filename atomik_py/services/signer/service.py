import io

from atomik_py.base import AtomikBase
from atomik_py.services.signer.models import SignerGetFileResponse
from atomik_py.services.signer.models import SignerSignResponse
from atomik_py.services.signer.models import SignerVerifyRespons
from atomik_py.utils import construct_model
from atomik_py.utils import prepare_file_for_request


class Signer:
    def __init__(self, root: AtomikBase):
        self.root = root

    def sign(self, file_stream: io.IOBase):
        response = self.root.make_authenticated_request(
            path="/api/services/signer/sign/",
            method="POST",
            files={"file": prepare_file_for_request(file_stream)},
        )
        if error := self.root.validate_response(response=response):
            return error
        response_json = response.json()
        return construct_model(
            SignerSignResponse,
            response=response,
            response_data={"tx_hash": response_json["tx_hash"]},
        )

    def verify(self, hash):  # noqa: A002
        response = self.root.make_authenticated_request(
            path="/api/services/signer/verify/",
            method="POST",
            json={"hash": hash},
        )
        if error := self.root.validate_response(response=response):
            return error
        response_json = response.json()
        return construct_model(
            SignerVerifyRespons,
            response=response,
            response_data={"tx_hash": response_json["tx_hash"]},
        )

    def get_file(self, hash):  # noqa: A002
        response = self.root.make_authenticated_request(
            path=f"/api/services/signer/files/{hash}/",
            method="GET",
        )
        if error := self.root.validate_response(response=response):
            return error
        response_json = response.json()
        return construct_model(
            SignerGetFileResponse,
            response=response,
            response_data={
                "file": response_json["file"],
                "hash": response_json["hash"],
                "tx_hash": response_json["tx_hash"],
                "hash_option": response_json["hash_option"],
            },
        )
