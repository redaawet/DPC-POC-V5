from dataclasses import dataclass, field


@dataclass
class Token:
    token_id: str
    value: int
    issuer_pk: str
    owner_pk: str
    expiry: str
    policy: dict
    issuer_signature: str
    transfer_chain: list[dict] = field(default_factory=list)
