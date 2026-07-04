import asyncio
from dataclasses import dataclass
import logging
from typing import Any

from closable import Closable

logger = logging.getLogger(__name__)

from . import AnySocketHandler


class FakeNetwork:
    """A shared in-memory network registry.

    Handlers register themselves under an (ip, port) key. Sending a message
    simply looks up the target handler and pushes the payload into its
    inbox_queue, mimicking the behaviour of the real SocketHandler without
    touching any real sockets.
    """

    def __init__(self) -> None:
        # (ip, port) -> InMemorySocketHandler
        self._endpoints: dict[tuple[str, int], "InMemorySocketHandler"] = {}

    async def create_handler(self, ip: str, port: int) -> "InMemorySocketHandler":
        h = InMemorySocketHandler(self)
        await h.start(ip, port)
        return h

    def _register(self, ip: str, port: int, handler: "InMemorySocketHandler") -> None:
        key = (ip, port)
        if key in self._endpoints:
            logger.warning("Endpoint %s:%s already registered, overwriting", ip, port)
        self._endpoints[key] = handler
        logger.info("Registered in-memory endpoint %s:%s", ip, port)

    def _unregister(self, ip: str, port: int) -> None:
        self._endpoints.pop((ip, port), None)
        logger.info("Unregistered in-memory endpoint %s:%s", ip, port)

    async def deliver(self, src_ip: str, dst_ip: str, dst_port: int, data: bytes) -> None:
        target = self._endpoints.get((dst_ip, dst_port))
        if target is None:
            logger.warning(
                "Failed to send to %s:%s: no in-memory endpoint registered",
                dst_ip,
                dst_port,
            )
            return

        logger.debug(
            "Delivering %d bytes from %s to %s:%s", len(data), src_ip, dst_ip, dst_port
        )
        # Mirror the real handler's inbox contract: (src_ip, data)
        await target.inbox_queue.put((src_ip, data))
        

class InMemorySocketHandler(Closable, AnySocketHandler):
    """Drop-in replacement for SocketHandler that uses a FakeNetwork.

    Exposes the same interface:
      - inbox_queue
      - outbox_queue
      - start()
    """

    def __init__(self, network: FakeNetwork) -> None:
        super().__init__()
        self.inbox_queue = asyncio.Queue()
        self.outbox_queue = asyncio.Queue()
        self.network = network
        self._host: str | None = None
        self._port: int | None = None

    async def _send_loop(self):
        while True:
            ip, port, data = await self.outbox_queue.get()
            # Dispatch each send as its own task to match the real handler's
            # concurrency behaviour.
            self.bind_closable(
                asyncio.create_task(self._connect_and_send(ip, port, data))
            )

    async def _connect_and_send(self, ip, port, data: bytes):
        logger.debug("Sending (in-memory) to %s:%s", ip, port)
        try:
            src_ip = self._host if self._host not in (None, "0.0.0.0") else "127.0.0.1"
            await self.network.deliver(src_ip, ip, port, data)
        except Exception as exc:
            logger.warning("Failed to send to %s:%s: %r", ip, port, exc)

    async def start(self, host="0.0.0.0", port=9009):
        self._host = host
        self._port = port

        # Register this handler so others can reach it via the fake network.
        self.network._register(host, port, self)
        logger.info("In-memory server 'listening' on %s:%s", host, port)

        self.bind_named_closable(self._send_loop.__name__, self._send_loop())
        
    async def stop(self):
        assert self.network
        assert self._host
        assert self._port
        self.network._unregister(self._host, self._port)
        self.bind_named_closable(self._send_loop.__name__, None)
        
    async def close(self):
        await super().close()
        if self._host is not None and self._port is not None:
            self.network._unregister(self._host, self._port)