from dpc.token.token_model import Token


class Ledger:
    def __init__(self) -> None:
        self._tokens: dict[str, Token] = {}

    def add(self, token: Token) -> None:
        self._tokens[token.token_id] = token

    def pop(self, token_id: str) -> Token:
        return self._tokens.pop(token_id)

    def get(self, token_id: str) -> Token:
        return self._tokens[token_id]

    def has(self, token_id: str) -> bool:
        return token_id in self._tokens
