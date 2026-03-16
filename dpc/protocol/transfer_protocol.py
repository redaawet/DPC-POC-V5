from collections import deque
from dpc.wallet.wallet import Wallet


class LocalChannel:
    def __init__(self) -> None:
        self._queue = deque()

    def send(self, data):
        self._queue.append(data)

    def receive(self):
        if not self._queue:
            return None
        return self._queue.popleft()


def transfer_over_channel(sender: Wallet, receiver: Wallet, token_id: str, channel: LocalChannel):
    token = sender.send(token_id, receiver)
    channel.send(token)
    return channel.receive()
