from dpc.crypto.signatures import verify_signature
from dpc.token.token_model import Token
from dpc.token.transfer_chain import validate_transfer_chain


def _issued_owner(token: Token) -> str:
    if token.transfer_chain:
        return token.transfer_chain[0]["from_pk"]
    return token.owner_pk


def _issuer_payload(token: Token) -> bytes:
    issued_owner = _issued_owner(token)
    return f"{token.token_id}|{token.value}|{token.issuer_pk}|{issued_owner}|{token.expiry}|{token.policy}".encode()


class ReconciliationService:
    def __init__(self) -> None:
        self._settled_tokens: set[str] = set()

    def reconcile(self, token: Token) -> tuple[bool, str]:
        if token.token_id in self._settled_tokens:
            return False, "double-spend detected"
        issuer_pk = bytes.fromhex(token.issuer_pk)
        if not verify_signature(issuer_pk, _issuer_payload(token), token.issuer_signature):
            return False, "invalid issuer signature"
        if not validate_transfer_chain(token):
            return False, "invalid transfer chain"
        self._settled_tokens.add(token.token_id)
        return True, "ok"
