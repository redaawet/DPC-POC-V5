from datetime import datetime, timedelta, timezone
from uuid import uuid4

from dpc.crypto.keys import generate_keypair, public_key_bytes
from dpc.crypto.signatures import sign_payload
from dpc.token.token_model import Token


class Issuer:
    def __init__(self) -> None:
        self.private_key, self.public_key = generate_keypair()
        self.public_key_hex = public_key_bytes(self.public_key)

    def mint_token(self, owner_pk: str, value: int, ttl_days: int = 30) -> Token:
        token_id = str(uuid4())
        expiry = (datetime.now(timezone.utc) + timedelta(days=ttl_days)).isoformat()
        policy = {"transferable": True}
        payload = f"{token_id}|{value}|{self.public_key_hex}|{owner_pk}|{expiry}|{policy}".encode()
        issuer_signature = sign_payload(self.private_key, payload)
        return Token(
            token_id=token_id,
            value=value,
            issuer_pk=self.public_key_hex,
            owner_pk=owner_pk,
            expiry=expiry,
            policy=policy,
            issuer_signature=issuer_signature,
        )
