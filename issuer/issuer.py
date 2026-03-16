"""Issuer (central bank simulator) for minting CBDC tokens."""
from __future__ import annotations

from copy import deepcopy

from crypto.crypto_utils import sign
from token.poc_models import Token


class Issuer:
    """Minting authority that signs root tokens."""

    def __init__(self, private_key_hex: str, public_key_hex: str) -> None:
        self.private_key_hex = private_key_hex
        self.public_key_hex = public_key_hex
        self.issued_tokens: dict[str, Token] = {}

    def mint_token(self, owner_pk: str, value: int) -> Token:
        """Mint and sign a token for an owner wallet."""
        token = Token.new_unsigned(value=value, issuer_pk=self.public_key_hex, owner_pk=owner_pk)
        token.issuer_signature = sign(token.signing_payload(), self.private_key_hex)
        self.issued_tokens[token.token_id] = deepcopy(token)
        return deepcopy(token)
