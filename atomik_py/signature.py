import base64
import hmac
import io
import json
from datetime import datetime
from typing import Any

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


def serialize_to_base64(data: Any) -> str | None:
    """
    Serializes various types of data into base64 strings or processes recursively.
    """
    if isinstance(data, str):
        return data  # Strings are returned as-is.
    if isinstance(data, io.IOBase):
        # Handle file-like or Django File objects.
        data.seek(0)  # Ensure the pointer is at the start.
        encoded_data = base64.b64encode(data.read()).decode()
        data.seek(0)  # Reset the pointer for further usage.
        return encoded_data
    if isinstance(data, tuple) and len(data) == 3:  # noqa: PLR2004
        # Handle the case where data is a tuple of (filename, file_stream, mime_type)
        filename, file_stream, mime_type = data
        file_stream.seek(0)  # Ensure file pointer is at the start
        encoded_data = base64.b64encode(
            file_stream.read(),
        ).decode()  # Base64 encode the file content
        file_stream.seek(0)  # Reset the pointer for further usage
        return encoded_data
    if isinstance(data, dict):
        return json_encode_with_base64(data)  # Process nested dictionaries recursively.
    if isinstance(data, list):
        return [
            serialize_to_base64(item) for item in data
        ]  # Process each list item recursively.
    return None  # Return None for unsupported types.


def json_encode_with_base64(data: dict | list) -> str:
    if isinstance(data, dict):
        obj = {key: serialize_to_base64(value) for key, value in data.items()}
    elif isinstance(data, list):
        obj = [serialize_to_base64(val) for val in data]
    return json.dumps(
        obj,
        separators=(",", ":"),
    )


def generate_signature_asymmetric(  # noqa: PLR0913
    private_key: RSA.RsaKey,
    client_id: str,
    http_method: str,
    endpoint_path: str,
    timestamp: datetime,
    request_body: dict,
):
    timestamp_iso = timestamp.isoformat(timespec="seconds")
    encoded_request_body = json_encode_with_base64(request_body)
    construct_string_to_sign = f"{client_id}|{http_method}|{endpoint_path}|{timestamp_iso}|{encoded_request_body}"  # noqa: E501
    digest = SHA256.new(bytes(construct_string_to_sign, "utf-8"))
    signature = PKCS1_v1_5.new(private_key).sign(digest)
    signature = base64.b64encode(signature).decode()
    return signature  # noqa: RET504


def generate_header(  # noqa: PLR0913
    private_key: RSA.RsaKey,
    client_id: str,
    http_method: str,
    endpoint_path: str,
    request_body: dict,
    timestamp: datetime | None = None,
):
    if not timestamp:
        timestamp = datetime.now()  # noqa: DTZ005
    headers = {
        "X-TIMESTAMP": timestamp.isoformat(timespec="seconds"),
        "X-SIGNATURE": generate_signature_asymmetric(
            client_id=client_id,
            timestamp=timestamp,
            private_key=private_key,
            http_method=http_method,
            endpoint_path=endpoint_path,
            request_body=request_body,
        ),
        "X-CLIENT-KEY": client_id,
    }
    return headers, timestamp


def generate_symmetric_signature(
    client_id: str,
    http_status: str,
    timestamp: datetime,
    response_body: dict,
):
    encoded_response_body = json_encode_with_base64(response_body)
    timestamp_iso = timestamp.isoformat(timespec="seconds")
    construct_string_to_sign = (
        f"{client_id}|{http_status}|{timestamp_iso}|{encoded_response_body}"
    )
    signature = hmac.new(
        client_id.encode(),
        construct_string_to_sign.encode(),
        SHA256,
    ).hexdigest()
    return signature  # noqa: RET504


def verify_symmetric_signature(
    client_id: str,
    http_status: str,
    timestamp: datetime,
    response_body: dict,
    received_signature: str,
):
    calculated_signature = generate_symmetric_signature(
        client_id,
        http_status,
        timestamp,
        response_body,
    )
    return hmac.compare_digest(calculated_signature, received_signature)
