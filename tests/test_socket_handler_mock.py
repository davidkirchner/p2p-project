"""
Can be removed as soon as the actual SocketHandler implementation is ready
"""

import asyncio

from socket_handler import SocketHandlerMock


def test_inbox_roundtrip():
    async def run():
        handler = SocketHandlerMock()
        await handler.inbox_queue.put(("192.168.0.5", b"incoming"))
        assert await handler.inbox_queue.get() == ("192.168.0.5", b"incoming")

    asyncio.run(run())


def test_outbox_roundtrip():
    async def run():
        handler = SocketHandlerMock()
        await handler.outbox_queue.put(("10.0.0.2", 2000, b"hello"))
        assert await handler.outbox_queue.get() == ("10.0.0.2", 2000, b"hello")

    asyncio.run(run())
