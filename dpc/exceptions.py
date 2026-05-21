"""Custom exception hierarchy for the Digital Pocket Cash PoC."""


class DPCError(Exception):
    """Base class for all Digital Pocket Cash errors."""


class PolicyViolationError(DPCError):
    """Raised when an offline risk policy is violated."""


class HopLimitExceededError(PolicyViolationError):
    """Raised when a token transfer exceeds the offline hop limit."""


class WalletBalanceCapError(PolicyViolationError):
    """Raised when a wallet would exceed the maximum offline balance."""


class TransactionValueCapError(PolicyViolationError):
    """Raised when a mint or transfer exceeds the single-transaction cap."""


class TokenExpiredError(PolicyViolationError):
    """Raised when a token is expired or local clock rollback is detected."""


class CryptographicError(DPCError):
    """Raised when a cryptographic validation fails."""


class SignatureVerificationError(CryptographicError):
    """Raised when an Ed25519 signature cannot be verified."""


class ChainIntegrityError(CryptographicError):
    """Raised when a transfer chain hash or ordering invariant fails."""


class SessionDecryptionError(CryptographicError):
    """Raised when a BLE session payload cannot be decrypted or authenticated."""


class DoubleSpendError(DPCError):
    """Raised when a token replay or double-spend attempt is detected."""


class ReconciliationError(DPCError):
    """Raised when issuer-side settlement cannot be completed."""


class FirstClaimConflictError(ReconciliationError):
    """Raised when a later settlement conflicts with the first valid claim."""


class WalletStateError(DPCError):
    """Raised when a wallet operation is invalid for the local UTR state."""


class InsufficientFundsError(WalletStateError):
    """Raised when a wallet cannot cover a requested payment amount."""
