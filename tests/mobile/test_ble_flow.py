from mobile.ble_adapter_stub import BleAdapterStub


def test_ble_stub_handshake_and_message_exchange() -> None:
    wallet_a_adapter = BleAdapterStub(device_id="wallet-a")
    wallet_b_adapter = BleAdapterStub(device_id="wallet-b")

    wallet_a_adapter.register_peer(wallet_b_adapter)
    wallet_b_adapter.register_peer(wallet_a_adapter)

    assert wallet_a_adapter.connect("wallet-b") is True
    assert wallet_b_adapter.connect("wallet-a") is True

    wallet_a_adapter.send('DISCOVERY:{"sender":"wallet-a","receiver":"wallet-b","session_id":"s-1"}')
    discovery = wallet_b_adapter.receive()
    assert discovery is not None
    assert "session_id" in discovery

    wallet_b_adapter.send('DISCOVERY_ACK:{"session_id":"s-1"}')
    ack = wallet_a_adapter.receive()
    assert ack is not None
    assert "DISCOVERY_ACK" in ack

    wallet_a_adapter.send('TRANSFER:{"session_id":"s-1","nonce":1,"token_json":"{}","transfer_signature":"sig"}')
    transfer = wallet_b_adapter.receive()
    assert transfer is not None
    assert "TRANSFER" in transfer
