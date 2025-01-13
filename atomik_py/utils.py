import io
import os
from typing import Any

import requests


def prepare_file_for_request(file_stream: io.IOBase):
    filename = os.path.basename(file_stream.name)  # noqa: PTH119
    return (filename, file_stream, "application/pdf")


def combine_request_body(data=None, json=None, files=None):
    if data is None:
        data = {}
    if json is None:
        json = {}
    if files is None:
        files = {}
    return data | json | files


def construct_model(model, response: requests.Response, response_data: Any):
    return model(
        ok=True,
        signature=response.headers["X-SIGNATURE"],
        timestamp_iso=response.headers["X-TIMESTAMP"],
        status_code=response.status_code,
        response=response_data,
    )
