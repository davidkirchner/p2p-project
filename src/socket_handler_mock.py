"""In-memory mock of the Network Layer (SocketHandler).

The real SocketHandler (see issue: "async TCP SocketHandler") sends and receives
raw bytes over TCP and talks to the rest of the app *exclusively* through two
``asyncio.Queue``s:

    inbox_queue   -> yields (sender_ip, data)            # received messages
    outbox_queue  <- accepts (dest_ip, dest_port, data)  # messages to send

That queue contract is all the Kademlia layer needs. This mock just exposes the
two queues so Kademlia can be developed before the real socket layer is done.
As soon as the real real SocketHandler is implemented, this can be removed/
replaced.
"""

import asyncio

# Queue item shapes, mirroring the real SocketHandler contract.
InboxItem = tuple[str, bytes]          # (sender_ip, data)
OutboxItem = tuple[str, int, bytes]    # (dest_ip, dest_port, data)


class SocketHandlerMock:
    """Stand-in for the real SocketHandler's queue interface."""

    def __init__(self) -> None:
        self.inbox_queue: asyncio.Queue[InboxItem] = asyncio.Queue()
        self.outbox_queue: asyncio.Queue[OutboxItem] = asyncio.Queue()
