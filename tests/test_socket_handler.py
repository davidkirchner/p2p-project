import asyncio
import socket
import struct
from unittest.mock import AsyncMock, Mock

import pytest

from socket_handler import SocketHandler


@pytest.fixture
def handler() -> SocketHandler:
    return SocketHandler()


def _mock_writer(peername=("127.0.0.1", 5555)) -> Mock:
    """A StreamWriter stand-in: sync write/close, awaitable drain/wait_closed."""
    writer = Mock(name="StreamWriter")
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    writer.get_extra_info.return_value = peername
    return writer


def _reader_with(data: bytes) -> asyncio.StreamReader:
    """A real StreamReader pre-loaded with ``data`` and at EOF."""
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


def _free_port() -> int:
    """Ask the OS for an unused TCP port on the loopback interface."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# construction
# ---------------------------------------------------------------------------

def test_starts_with_empty_queues(handler: SocketHandler):
    assert handler.inbox_queue.empty()
    assert handler.outbox_queue.empty()


# ---------------------------------------------------------------------------
# send_message: wire framing
# ---------------------------------------------------------------------------

async def test_send_message_writes_length_prefixed_frame(handler: SocketHandler):
    writer = _mock_writer()

    await handler._write_message(writer, b"hello")

    expected = struct.pack("!I", len(b"hello")) + b"hello"
    writer.write.assert_called_once_with(expected)
    writer.drain.assert_awaited_once()


async def test_send_message_handles_empty_payload(handler: SocketHandler):
    writer = _mock_writer()

    await handler._write_message(writer, b"")

    writer.write.assert_called_once_with(struct.pack("!I", 0))


# ---------------------------------------------------------------------------
# _read_message: frame parsing
# ---------------------------------------------------------------------------

async def test_read_message_returns_payload(handler: SocketHandler):
    reader = _reader_with(struct.pack("!I", 5) + b"hello")

    assert await handler._read_message(reader) == b"hello"


async def test_read_message_reads_exactly_one_frame(handler: SocketHandler):
    # Two frames back to back: only the first should be consumed.
    frame = struct.pack("!I", 3) + b"abc"
    reader = _reader_with(frame + struct.pack("!I", 2) + b"de")

    assert await handler._read_message(reader) == b"abc"


async def test_read_message_empty_payload(handler: SocketHandler):
    reader = _reader_with(struct.pack("!I", 0))

    assert await handler._read_message(reader) == b""


async def test_read_message_truncated_header_raises(handler: SocketHandler):
    reader = _reader_with(b"\x00\x00")  # fewer than the 4 header bytes

    with pytest.raises(asyncio.IncompleteReadError):
        await handler._read_message(reader)


async def test_read_message_truncated_body_raises(handler: SocketHandler):
    reader = _reader_with(struct.pack("!I", 10) + b"short")  # claims 10, sends 5

    with pytest.raises(asyncio.IncompleteReadError):
        await handler._read_message(reader)


async def test_send_then_read_roundtrip(handler: SocketHandler):
    """What send_message writes must be exactly what _read_message parses."""
    chunks: list[bytes] = []
    writer = _mock_writer()
    writer.write.side_effect = chunks.append

    payload = b"round-trip payload \x00\xff"
    await handler._write_message(writer, payload)

    reader = _reader_with(b"".join(chunks))
    assert await handler._read_message(reader) == payload


# ---------------------------------------------------------------------------
# _handle_client: server-side connection handling
# ---------------------------------------------------------------------------

async def test_handle_client_enqueues_source_ip_and_data(handler: SocketHandler):
    reader = _reader_with(struct.pack("!I", 3) + b"abc")
    writer = _mock_writer(peername=("10.0.0.9", 4321))

    await handler._handle_client(reader, writer)

    assert handler.inbox_queue.get_nowait() == ("10.0.0.9", b"abc")
    writer.close.assert_called_once()
    writer.wait_closed.assert_awaited_once()


async def test_handle_client_closes_writer_on_incomplete_read(handler: SocketHandler):
    reader = _reader_with(b"\x00")  # truncated header -> IncompleteReadError
    writer = _mock_writer()

    await handler._handle_client(reader, writer)  # must not raise

    assert handler.inbox_queue.empty()
    writer.close.assert_called_once()
    writer.wait_closed.assert_awaited_once()


# ---------------------------------------------------------------------------
# end-to-end: two fully started handlers talking over loopback
# ---------------------------------------------------------------------------

async def test_message_travels_from_sender_to_receiver():
    """A real send/receive round trip across two independent handlers."""
    receiver = SocketHandler()
    sender = SocketHandler()
    receiver_port = _free_port()

    async with receiver, sender:
        # start() only returns once the listening socket is bound, so the
        # receiver is guaranteed to be accepting connections from here on.
        await receiver.start(host="127.0.0.1", port=receiver_port)
        await sender.start(host="127.0.0.1", port=_free_port())

        await sender.outbox_queue.put(("127.0.0.1", receiver_port, b"via loop"))
        src_ip, data = await asyncio.wait_for(receiver.inbox_queue.get(), timeout=2.0)

    assert src_ip == "127.0.0.1"
    assert data == b"via loop"


async def test_send_loop_survives_failed_connection():
    """A send to an unreachable peer is logged, not fatal: the loop keeps going."""
    receiver = SocketHandler()
    sender = SocketHandler()
    receiver_port = _free_port()

    async with receiver, sender:
        await receiver.start(host="127.0.0.1", port=receiver_port)
        await sender.start(host="127.0.0.1", port=_free_port())

        # Port 1 is not listening -> open_connection raises, loop must recover...
        await sender.outbox_queue.put(("127.0.0.1", 1, b"doomed"))
        # ...so the next, deliverable message still gets through.
        await sender.outbox_queue.put(("127.0.0.1", receiver_port, b"survivor"))

        _, data = await asyncio.wait_for(receiver.inbox_queue.get(), timeout=2.0)

    assert data == b"survivor"


# ---------------------------------------------------------------------------
# start(): wiring of background tasks
# ---------------------------------------------------------------------------

async def test_start_is_listening_once_it_returns(handler: SocketHandler):
    port = _free_port()

    await handler.start(host="127.0.0.1", port=port)
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.close()
        await writer.wait_closed()

        assert isinstance(handler.get_named_closable("_send_loop"), asyncio.Task)
        assert isinstance(handler.get_named_closable("_serve"), asyncio.Task)
    finally:
        await handler.close()


async def test_close_stops_serving(handler: SocketHandler):
    port = _free_port()
    await handler.start(host="127.0.0.1", port=port)

    await handler.close()

    # Server torn down: the port no longer accepts connections.
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", port)
