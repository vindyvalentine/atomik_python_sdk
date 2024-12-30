from Crypto.PublicKey import RSA

from atomik_py.base import AtomikBase
from atomik_py.services import Signer


class Atomik(AtomikBase):
    def __init__(
        self,
        private_key: RSA.RsaKey,
        client_id: str,
        client_secret: str,
        base_url: str,
        timeout: int = 15,
    ):
        self.private_key = private_key
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url
        self.access_token = None
        self.token_expiration = None
        self.timeout = timeout

        # Assign services
        self.signer = Signer(self)
