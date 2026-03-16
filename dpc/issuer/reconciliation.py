from dpc.token.token_model import Token
from dpc.token.transfer_chain import validate_transfer_chain


class ReconciliationService:
    def __init__(self) -> None:
        self._settled_tokens: set[str] = set()

    def reconcile(self, token: Token) -> tuple[bool, str]:
        if token.token_id in self._settled_tokens:
            return False, "double-spend detected"
        if not validate_transfer_chain(token):
            return False, "invalid transfer chain"
        self._settled_tokens.add(token.token_id)
        return True, "ok"
