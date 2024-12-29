import io

from atomik_py.models import SignerGetFileResponse
from atomik_py.models import SignerSignResponse
from atomik_py.models import SignerVerifyRespons

from .base import AtomikBase
from .utils import construct_model
from .utils import prepare_file_for_requests


class Atomik(AtomikBase):
    def sign(self, file_stream: io.IOBase):
        response = self.make_authenticated_request(
            path="/api/services/signer/sign/",
            method="POST",
            files={"file": prepare_file_for_requests(file_stream)},
        )
        if error := self.validate_response(response=response):
            return error
        response_json = response.json()
        return construct_model(
            SignerSignResponse,
            response=response,
            response_data={"tx_hash": response_json["tx_hash"]},
        )

    def verify(self, hash):  # noqa: A002
        response = self.make_authenticated_request(
            path="/api/services/signer/verify/",
            method="POST",
            json={"hash": hash},
        )
        if error := self.validate_response(response=response):
            return error
        response_json = response.json()
        return construct_model(
            SignerVerifyRespons,
            response=response,
            response_data={"tx_hash": response_json["tx_hash"]},
        )

    def get_file(self, hash):  # noqa: A002
        response = self.make_authenticated_request(
            path=f"/api/services/signer/files/{hash}/",
            method="GET",
        )
        if error := self.validate_response(response=response):
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
