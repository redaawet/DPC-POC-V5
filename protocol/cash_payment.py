"""High-level cash-like payment protocol."""

from __future__ import annotations

from protocol.payment_session import PaymentSession
from wallet.wallet import Wallet


def execute_cash_payment(sender_wallet: Wallet, receiver_wallet: Wallet, price: int) -> tuple[list[str], list[str]]:
    """Run a cash-like payment where receiver returns change using own tokens."""
    session = PaymentSession(sender_wallet=sender_wallet, receiver_wallet=receiver_wallet, price=price)
    return session.execute()
