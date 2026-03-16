from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dpc.issuer.mint import Issuer
from dpc.issuer.reconciliation import ReconciliationService
from dpc.protocol.transfer_protocol import LocalChannel, transfer_over_channel
from dpc.wallet.wallet import Wallet


def main() -> None:
    issuer = Issuer()
    reconciler = ReconciliationService()
    wallet_a, wallet_b, wallet_c = Wallet("A"), Wallet("B"), Wallet("C")

    token = issuer.mint_token(wallet_a.public_key_hex, 100)
    wallet_a.receive(token)

    channel = LocalChannel()
    transfer_over_channel(wallet_a, wallet_b, token.token_id, channel)
    transfer_over_channel(wallet_b, wallet_c, token.token_id, channel)

    final_token = wallet_c.ledger.get(token.token_id)
    ok, message = reconciler.reconcile(final_token)

    print("Transfer chain:")
    for step in final_token.transfer_chain:
        print(step)
    print(f"Reconciliation result: {ok} ({message})")


if __name__ == "__main__":
    main()
