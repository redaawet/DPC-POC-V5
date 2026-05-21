"""Policy and serialization constants for the Digital Pocket Cash PoC."""

MAX_OFFLINE_HOPS: int = 7
MAX_WALLET_BALANCE_SUBUNITS: int = 1_000_000
MAX_SINGLE_TX_SUBUNITS: int = 100_000
TOKEN_TTL_SECONDS: int = 604_800

SUBUNITS_PER_ETB: int = 100

GENESIS_HASH: str = "0" * 64
NONCE_BYTES: int = 16

JSON_SEPARATORS: tuple[str, str] = (",", ":")
