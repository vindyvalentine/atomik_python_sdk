import base64
import time
from dataclasses import dataclass
from dataclasses import fields
from datetime import datetime
from typing import Generic
from typing import Literal
from typing import TypeVar

import requests
from Crypto.PublicKey import RSA

from atomik_py.exceptions import AtomikBaseError

from .signature import generate_header
from .signature import verify_symmetric_signature
from .utils import combine_request_body

T = TypeVar("T")


class AtomikBase:
    def __init__(
        self,
        private_key: RSA.RsaKey,
        client_id: str,
        client_secret: str,
        base_url: str,
    ):
        self.private_key = private_key
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url
        self.access_token = None
        self.token_expiration = None

    def _get_token(self):
        auth_value = f"{self.client_id}:{self.client_secret}"
        base64_auth_value = base64.b64encode(auth_value.encode("utf-8")).decode("utf-8")

        headers = {
            "Authorization": f"Basic {base64_auth_value}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = {"grant_type": "client_credentials"}

        response = requests.post(
            f"{self.base_url}/oauth/token/",
            headers=headers,
            data=data,
            timeout=10,
        )

        if response.status_code == 200:  # noqa: PLR2004
            token_data = response.json()
            self.access_token = token_data.get("access_token")
            expires_in = token_data.get(
                "expires_in",
                3600,
            )  # Default expiration time is 1 hour
            self.token_expiration = time.time() + expires_in
            return self.access_token
        raise AtomikBaseError(
            "Error getting access token",
        )

    def get_access_token(self):
        if self.access_token is None or self._is_token_expired():
            return self._get_token()
        return self.access_token

    def _is_token_expired(self):
        return time.time() >= self.token_expiration

    def make_authenticated_request(  # noqa: PLR0913
        self,
        path: str,
        method="GET",
        data=None,
        json=None,
        files=None,
        headers=None,
    ):
        access_token = self.get_access_token()

        if headers is None:
            headers = {}

        method = method.upper()

        headers["Authorization"] = f"Bearer {access_token}"
        headers = (
            headers
            | generate_header(
                private_key=self.private_key,
                client_id=self.client_id,
                http_method=method,
                endpoint_path=path,
                request_body=combine_request_body(data, json, files),
            )[0]
        )

        response: requests.Response = requests.request(
            method=method,
            url=f"{self.base_url}{path}",
            headers=headers,
            data=data,
            json=json,
            files=files,
            timeout=10,
        )
        return response

    @staticmethod
    def handle_error(response: requests.Response):
        if response.status_code != 200:  # noqa: PLR2004
            return AtomikErrorResponse(
                ok=False,
                signature=response.headers["X-SIGNATURE"],
                timestamp_iso=response.headers["X-TIMESTAMP"],
                status_code=str(response.status_code),
                error=response.json(),
            )
        return None

    def validate_response(self, response: requests.Response):
        signature = response.headers["X-SIGNATURE"]
        timestamp = datetime.fromisoformat(response.headers["X-TIMESTAMP"])
        status_code = str(response.status_code)
        verified = verify_symmetric_signature(
            client_id=self.client_id,
            timestamp=timestamp,
            http_status=status_code,
            response_body=response.json(),
            received_signature=signature,
        )
        if not verified:
            pass  # FIXME

        return self.handle_error(response=response)


@dataclass
class AtomikErrorDetailResponse:
    detail: str | list[str]


@dataclass
class AtomikErrorResponse:
    ok: Literal[False]
    signature: str
    timestamp_iso: str
    status_code: str
    error: AtomikErrorDetailResponse

    def __post_init__(self):
        if isinstance(self.error, dict):
            try:
                self.error = AtomikErrorDetailResponse(**self.error)
            except Exception as e:
                raise TypeError(
                    "Failed to convert dict to AtomikErrorDetailResponse",
                ) from e

        elif isinstance(self.error, list):
            try:
                self.error = AtomikErrorDetailResponse(
                    detail=[item for item in self.error if isinstance(item, str)],
                )

            except Exception as e:
                raise TypeError(
                    "Failed to convert list elements to AtomikErrorDetailResponse",
                ) from e

        if not isinstance(self.error, (AtomikErrorDetailResponse, list)):
            raise TypeError("Unsupported type")


@dataclass
class AtomikBaseResponse(Generic[T]):
    ok: Literal[True]
    signature: str
    timestamp_iso: str
    status_code: str
    response: T

    def __post_init__(self):
        response_field = next((f for f in fields(self) if f.name == "response"), None)

        if response_field:
            expected_type = response_field.type
            if isinstance(self.response, dict):
                try:
                    self.response = expected_type(**self.response)
                except Exception as e:
                    raise TypeError(
                        "Failed to convert dict",
                    ) from e

            if not isinstance(self.response, expected_type):
                raise TypeError(
                    "Unsupported type",
                )


def mixin_base_response(target_dataclass: type[T]):
    def decorator(cls: type[T]) -> type[AtomikBaseResponse[T]]:
        new_class_name = f"New{target_dataclass.__name__}"

        new_class = type(
            new_class_name,
            (AtomikBaseResponse,),
            {
                "__annotations__": {
                    **{
                        f.name: f.type
                        for f in fields(AtomikBaseResponse)
                        if f.name != "response"
                    },
                    "response": dataclass(target_dataclass),
                },
                "__module__": __name__,
            },
        )

        return dataclass(new_class)

    return decorator(target_dataclass)
