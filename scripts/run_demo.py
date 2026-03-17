"""Demo: cash-like payment where receiver returns change with own tokens."""

from crypto.signatures import generate_keypair, sign_message
from protocol.cash_payment import execute_cash_payment
from token.token_model import Token
from wallet.wallet import DictKeyStore, Wallet


def mint(issuer_sk: str, issuer_pk: str, owner_pk: str, token_id: str, value: int) -> Token:
    token = Token(
        token_id=token_id,
        value=value,
        issuer_pk=issuer_pk,
        owner_pk=owner_pk,
        expiry="2030-01-01T00:00:00+00:00",
        issuer_signature="",
        transfer_chain=[],
    )
    token.issuer_signature = sign_message(issuer_sk, token.issuance_payload())
    return token


def wallet_values(wallet: Wallet) -> list[int]:
    return sorted(token.value for token in wallet.utr.values())


def main() -> None:
    issuer_sk, issuer_pk = generate_keypair()
    a_sk, a_pk = generate_keypair()
    b_sk, b_pk = generate_keypair()

    keystore = DictKeyStore()
    keystore.add_keypair(a_sk, a_pk)
    keystore.add_keypair(b_sk, b_pk)

    wallet_a = Wallet(owner_pk=a_pk, keystore=keystore)
    wallet_b = Wallet(owner_pk=b_pk, keystore=keystore)

    print("1) Issuer mints tokens")
    wallet_a.add_token(mint(issuer_sk, issuer_pk, a_pk, "a-10", 10))

    print("2) Wallet A withdraws [10]")
    wallet_b.add_token(mint(issuer_sk, issuer_pk, b_pk, "b-2a", 2))
    wallet_b.add_token(mint(issuer_sk, issuer_pk, b_pk, "b-2b", 2))
    wallet_b.add_token(mint(issuer_sk, issuer_pk, b_pk, "b-1", 1))

    print("3) Wallet B holds [2,2,1]")
    print("A:", wallet_values(wallet_a), "B:", wallet_values(wallet_b))

    execute_cash_payment(sender_wallet=wallet_a, receiver_wallet=wallet_b, price=6)

    print("4) Wallet A pays B price 6")
    print("5) Wallet B returns change [2,2]")
    print("6) Final wallet states")
    print("A:", wallet_values(wallet_a))
    print("B:", wallet_values(wallet_b))


if __name__ == "__main__":
    main()
