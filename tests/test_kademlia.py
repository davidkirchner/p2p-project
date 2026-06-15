import os
import asyncio
import hashlib
import contextlib

import pytest
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from kademlia import (
    KademliaMsg,
    KademliaNode,
    KADEMLIA_PORT,
    MsgType,
    Payload,
    Peer,
    PingPayload,
    PongPayload,
    StorePayload,
    StoreReplyPayload,
    FindNodePayload,
    FindNodeReplyPayload,
    FindValuePayload,
    FindValueReplyPayload,
    _Pending,
)

# Queue item shapes, mirroring the real SocketHandler contract.
InboxItem = tuple[str, bytes]          # (sender_ip, data)
OutboxItem = tuple[str, int, bytes]    # (dest_ip, dest_port, data)

class SocketHandlerMock:
    """Stand-in for the real SocketHandler's queue interface."""

    def __init__(self) -> None:
        self.inbox_queue: asyncio.Queue[InboxItem] = asyncio.Queue()
        self.outbox_queue: asyncio.Queue[OutboxItem] = asyncio.Queue()

# Schlüsselpaar erzeugen
priv = Ed25519PrivateKey.generate()
pub = priv.public_key()

# Public Key als rohe 32 Bytes
pub_raw = pub.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
sender_id = hashlib.sha256(pub_raw).digest()


def make_msg(msg_type, payload, **overrides):
    kwargs = dict(
        msg_type=msg_type,
        msg_id=uuid4().bytes,
        sender_id=sender_id,
        sender_pubkey=pub_raw,
        payload=payload,
        signature=b"dummy-sig",
    )
    kwargs.update(overrides)
    return KademliaMsg(**kwargs)



def test_empty_dict_payload_is_coerced():
    # {} für PING soll zum PingPayload werden (Abwärtskompatibilität).
    msg = make_msg(MsgType.PING, {})
    assert isinstance(msg.payload, PingPayload)


def test_sender_id_is_verified():
    # sender_id == sha256(pub_key) => should not raise
    assert make_msg(MsgType.PING, PingPayload())

    # sender_id != sha256(pub_key)
    with pytest.raises(ValueError):
        make_msg(
            MsgType.PING,
            PingPayload(),
            sender_id=hashlib.sha256(b"foo").digest(),
        )


def test_to_bytes_returns_bytes():
    msg = make_msg(MsgType.PING, PingPayload())
    assert isinstance(msg.to_bytes(), bytes)


def test_payload_type_must_match_msg_type():
    # FIND_NODE with wrong Payload (Ping) should raise
    with pytest.raises(ValueError):
        make_msg(MsgType.FIND_NODE, PingPayload())


@pytest.mark.parametrize(
    "msg_type, payload",
    [
        (MsgType.PING, PingPayload()),
        (MsgType.PONG, PongPayload()),
        (MsgType.STORE, StorePayload(key=os.urandom(32), value=os.urandom(50))),
        (MsgType.STORE_REPLY, StoreReplyPayload(success=True)),
        (MsgType.FIND_NODE, FindNodePayload(target=os.urandom(32))),
        (
            MsgType.FIND_NODE_REPLY,
            FindNodeReplyPayload(
                nodes=[Peer(node_id=os.urandom(32), ip="10.0.0.1")]
            ),
        ),
        (MsgType.FIND_VALUE, FindValuePayload(key=os.urandom(32))),
        (
            MsgType.FIND_VALUE_REPLY,
            FindValueReplyPayload(value=os.urandom(80)),
        ),
        (
            MsgType.FIND_VALUE_REPLY,
            FindValueReplyPayload(
                nodes=[Peer(node_id=os.urandom(32), ip="10.0.0.2")]
            ),
        ),
    ],
)
def test_payload_roundtrip(msg_type: MsgType, payload: Payload):
    msg = make_msg(msg_type, payload, in_reply_to=uuid4().bytes)
    parsed = KademliaMsg.from_bytes(msg.to_bytes())
    assert parsed == msg
    assert type(parsed.payload) is type(payload)


def test_binary_signature_roundtrip():
    # echte binäre Signatur (kein gültiges UTF-8) muss verlustfrei durchlaufen.
    sig = os.urandom(64)
    msg = make_msg(MsgType.PING, PingPayload(), signature=sig)
    parsed = KademliaMsg.from_bytes(msg.to_bytes())
    assert parsed.signature == sig


# =============================================================================
# KademliaNode tests
# =============================================================================
#
# Test helpers. A node is built around a SocketHandlerMock and talks to the
# outside world *only* through its two queues:
#
#   inbox_queue   -> (sender_ip, raw_bytes)        # things to handle
#   outbox_queue  <- (dest_ip, dest_port, raw_bytes)  # things it emits
#
# So the tests drive a node by putting bytes on its inbox and asserting on what
# shows up on its outbox -- no real networking involved.


def new_identity() -> tuple[bytes, bytes]:
    """A fresh (node_id, pubkey) pair with node_id == sha256(pubkey).

    The pubkey does not have to be a real key for these tests: KademliaMsg only
    checks that sender_id == sha256(sender_pubkey).
    """
    pubkey = os.urandom(32)
    return hashlib.sha256(pubkey).digest(), pubkey


def build_node(*, port: int = KADEMLIA_PORT) -> KademliaNode:
    """Build a KademliaNode with its own mock socket and a valid identity.

    Must be called from within a running event loop (KademliaNode grabs the
    loop in __init__).
    """
    node_id, pubkey = new_identity()
    return KademliaNode(SocketHandlerMock(), node_id, pubkey, port=port)


async def get_outbox(node: KademliaNode, timeout: float = 1.0):
    """Pop one (dest_ip, dest_port, data) off the outbox, failing fast.

    Wrapping the queue read in a timeout keeps a buggy node from hanging the
    whole test run -- a missing reply surfaces as a TimeoutError instead.
    """
    return await asyncio.wait_for(node.socket.outbox_queue.get(), timeout)


async def get_reply(node: KademliaNode, timeout: float = 1.0):
    """Like get_outbox, but also parse the bytes back into a KademliaMsg."""
    dest_ip, dest_port, data = await get_outbox(node, timeout)
    return dest_ip, dest_port, KademliaMsg.from_bytes(data)


@contextlib.asynccontextmanager
async def recv_loop_running(node: KademliaNode):
    """Run ``node.recv_loop()`` for the duration of the block, then tear down."""
    task = asyncio.ensure_future(node.recv_loop())
    try:
        yield task
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


class FakeNetwork:
    """Routes messages between nodes by IP, wiring their queues together.

    Each registered node gets two background tasks: its ``recv_loop`` and a
    pump that drains its outbox and forwards every message to the destination
    node's inbox (stamping the source IP, as the real socket layer would).
    Two real nodes can then talk end-to-end without any sockets.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, KademliaNode] = {}
        self._tasks: list[asyncio.Task] = []

    def add_node(self, ip: str, node: KademliaNode) -> KademliaNode:
        self._nodes[ip] = node
        self._tasks.append(asyncio.ensure_future(node.recv_loop()))
        self._tasks.append(asyncio.ensure_future(self._pump(ip, node)))
        return node

    async def _pump(self, src_ip: str, node: KademliaNode) -> None:
        while True:
            dest_ip, _dest_port, data = await node.socket.outbox_queue.get()
            dest = self._nodes.get(dest_ip)
            if dest is not None:
                await dest.socket.inbox_queue.put((src_ip, data))

    async def aclose(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)


@pytest.fixture
async def node() -> KademliaNode:
    """A single, isolated node (no recv_loop running)."""
    return build_node()


@pytest.fixture
async def network():
    net = FakeNetwork()
    try:
        yield net
    finally:
        await net.aclose()


class TestKademliaNode:
    """Behavioural tests for the Kademlia RPC engine."""

    # ---- get_k_nearest_neighbors --------------------------------------------

    async def test_knn_returns_all_when_not_more_than_k(self, node: KademliaNode):
        peers = [Peer(node_id=os.urandom(32), ip=f"10.0.0.{i}") for i in range(3)]
        node.peers = peers
        # 3 peers, k=5 -> all of them, untouched.
        assert node.get_k_nearest_neighbors(os.urandom(32), k=5) == peers

    async def test_knn_returns_closest_k_by_xor_distance(self, node: KademliaNode):
        # Target all-zeros => XOR distance of a peer equals its own id, so the
        # ordering is just the numeric order of the leading byte.
        target = bytes(32)
        ids = [5, 3, 9, 1, 7, 2]
        node.peers = [
            Peer(node_id=bytes([i]) + bytes(31), ip=f"10.0.0.{i}") for i in ids
        ]

        nearest = node.get_k_nearest_neighbors(target, k=3)

        assert [p.node_id[0] for p in nearest] == [1, 2, 3]

    async def test_knn_honours_custom_k(self, node: KademliaNode):
        node.peers = [Peer(node_id=os.urandom(32), ip=f"10.0.0.{i}") for i in range(10)]
        assert len(node.get_k_nearest_neighbors(os.urandom(32), k=4)) == 4

    async def test_knn_raises_on_id_length_mismatch(self, node: KademliaNode):
        node.peers = [
            Peer(node_id=os.urandom(16), ip="10.0.0.1"),  # wrong length
            Peer(node_id=os.urandom(32), ip="10.0.0.2"),
        ]
        # k=1 with 2 peers forces the distance computation (no early return).
        with pytest.raises(ValueError):
            node.get_k_nearest_neighbors(os.urandom(32), k=1)

    # ---- message construction / _send ---------------------------------------

    async def test_new_msg_is_signed_with_own_identity(self, node: KademliaNode):
        reply_to = uuid4().bytes
        msg = node._new_msg(MsgType.PING, PingPayload(), in_reply_to=reply_to)
        assert msg.sender_id == node.node_id
        assert msg.sender_pubkey == node.pubkey
        assert msg.in_reply_to == reply_to
        assert isinstance(msg.payload, PingPayload)

    async def test_send_uses_well_known_port_not_node_port(self):
        # The node's own listen port must not leak into the destination port:
        # messages always go to the network-wide KADEMLIA_PORT.
        node = build_node(port=1234)
        msg = node._new_msg(MsgType.PING, PingPayload())
        await node._send("203.0.113.7", msg)
        dest_ip, dest_port, data = await get_outbox(node)
        assert dest_ip == "203.0.113.7"
        assert dest_port == KADEMLIA_PORT
        assert KademliaMsg.from_bytes(data).msg_id == msg.msg_id

    # ---- request() correlation & timeout ------------------------------------

    async def test_request_times_out_and_cleans_up_pending(self, node: KademliaNode):
        msg = node._new_msg(MsgType.PING, PingPayload())
        with pytest.raises(asyncio.TimeoutError):
            await node.request("198.51.100.1", msg, timeout=0.01)
        # The outstanding-request registration must be gone after a timeout.
        assert msg.msg_id not in node._pending

    async def test_ping_returns_false_on_timeout(self, node: KademliaNode):
        assert await node.ping("198.51.100.1", timeout=0.01) is False

    # ---- handle_msg: reply correlation rules --------------------------------

    async def test_unsolicited_reply_is_ignored(self, node: KademliaNode):
        # A reply nobody is waiting for must be dropped silently.
        reply = make_msg(MsgType.PONG, PongPayload(), in_reply_to=uuid4().bytes)
        await node.handle_msg("198.51.100.1", reply)
        assert node.socket.outbox_queue.empty()

    async def test_reply_from_wrong_ip_does_not_resolve(self, node: KademliaNode):
        fut = node.loop.create_future()
        req_id = uuid4().bytes
        node._pending[req_id] = _Pending(fut, "10.0.0.9", MsgType.PONG)

        reply = make_msg(MsgType.PONG, PongPayload(), in_reply_to=req_id)
        await node.handle_msg("10.0.0.99", reply)  # right msg_id, wrong peer

        assert not fut.done()

    async def test_reply_with_wrong_type_does_not_resolve(self, node: KademliaNode):
        fut = node.loop.create_future()
        req_id = uuid4().bytes
        node._pending[req_id] = _Pending(fut, "10.0.0.9", MsgType.PONG)

        # Right peer & msg_id, but a FIND_NODE_REPLY where a PONG was expected.
        reply = make_msg(
            MsgType.FIND_NODE_REPLY, FindNodeReplyPayload(), in_reply_to=req_id
        )
        await node.handle_msg("10.0.0.9", reply)

        assert not fut.done()

    async def test_matching_reply_resolves_pending(self, node: KademliaNode):
        fut = node.loop.create_future()
        req_id = uuid4().bytes
        node._pending[req_id] = _Pending(fut, "10.0.0.9", MsgType.PONG)

        reply = make_msg(MsgType.PONG, PongPayload(), in_reply_to=req_id)
        await node.handle_msg("10.0.0.9", reply)

        assert fut.done()
        assert fut.result() == reply

    # ---- handle_msg: request handlers ---------------------------------------

    async def test_ping_request_is_answered_with_pong(self, node: KademliaNode):
        req = make_msg(MsgType.PING, PingPayload())
        await node.handle_msg("203.0.113.5", req)

        dest_ip, dest_port, reply = await get_reply(node)
        assert dest_ip == "203.0.113.5"
        assert dest_port == KADEMLIA_PORT
        assert reply.msg_type is MsgType.PONG
        assert reply.in_reply_to == req.msg_id

    async def test_store_request_persists_value_and_acks(self, node: KademliaNode):
        value = os.urandom(40)
        key = hashlib.sha256(value).digest()
        req = make_msg(MsgType.STORE, StorePayload(key=key, value=value))

        await node.handle_msg("203.0.113.5", req)

        assert node.dht[key] == value
        _, _, reply = await get_reply(node)
        assert reply.msg_type is MsgType.STORE_REPLY
        assert isinstance(reply.payload, StoreReplyPayload)
        assert reply.payload.success is True

    async def test_store_reply_is_correlatable(self, node: KademliaNode):
        value = os.urandom(40)
        key = hashlib.sha256(value).digest()
        req = make_msg(MsgType.STORE, StorePayload(key=key, value=value))
        await node.handle_msg("203.0.113.5", req)
        _, _, reply = await get_reply(node)
        assert reply.in_reply_to == req.msg_id

    async def test_find_node_request_returns_known_peers(self, node: KademliaNode):
        node.peers = [Peer(node_id=os.urandom(32), ip="9.9.9.9")]
        req = make_msg(MsgType.FIND_NODE, FindNodePayload(target=os.urandom(32)))

        await node.handle_msg("203.0.113.5", req)

        _, _, reply = await get_reply(node)
        assert reply.msg_type is MsgType.FIND_NODE_REPLY
        assert reply.in_reply_to == req.msg_id
        assert isinstance(reply.payload, FindNodeReplyPayload)
        assert reply.payload.nodes == node.peers

    async def test_find_value_hit_returns_value(self, node: KademliaNode):
        value = os.urandom(20)
        key = os.urandom(32)
        node.dht[key] = value
        req = make_msg(MsgType.FIND_VALUE, FindValuePayload(key=key))

        await node.handle_msg("203.0.113.5", req)

        _, _, reply = await get_reply(node)
        assert reply.msg_type is MsgType.FIND_VALUE_REPLY
        assert reply.in_reply_to == req.msg_id
        assert isinstance(reply.payload, FindValueReplyPayload)
        assert reply.payload.value == value
        assert reply.payload.nodes == []

    async def test_find_value_miss_returns_neighbors(self, node: KademliaNode):
        node.peers = [Peer(node_id=os.urandom(32), ip="9.9.9.9")]
        req = make_msg(MsgType.FIND_VALUE, FindValuePayload(key=os.urandom(32)))

        await node.handle_msg("203.0.113.5", req)

        _, _, reply = await get_reply(node)
        assert reply.msg_type is MsgType.FIND_VALUE_REPLY
        assert isinstance(reply.payload, FindValueReplyPayload)
        assert reply.payload.value is None
        assert reply.payload.nodes == node.peers

    async def test_find_value_miss_reply_is_correlatable(self, node: KademliaNode):
        req = make_msg(MsgType.FIND_VALUE, FindValuePayload(key=os.urandom(32)))
        await node.handle_msg("203.0.113.5", req)
        _, _, reply = await get_reply(node)
        assert reply.in_reply_to == req.msg_id

    # ---- recv_loop -----------------------------------------------------------

    async def test_recv_loop_dispatches_valid_message(self, node: KademliaNode):
        async with recv_loop_running(node):
            req = make_msg(MsgType.PING, PingPayload())
            await node.socket.inbox_queue.put(("203.0.113.5", req.to_bytes()))

            _, _, reply = await get_reply(node)
            assert reply.msg_type is MsgType.PONG
            assert reply.in_reply_to == req.msg_id

    async def test_recv_loop_drops_malformed_and_keeps_serving(self, node: KademliaNode):
        async with recv_loop_running(node):
            # Garbage first: it must be dropped without killing the loop.
            await node.socket.inbox_queue.put(("203.0.113.5", b"not-valid-json"))
            # A valid request right after must still be answered.
            req = make_msg(MsgType.PING, PingPayload())
            await node.socket.inbox_queue.put(item=("203.0.113.5", req.to_bytes()))

            _, _, reply = await get_reply(node)
            assert reply.msg_type is MsgType.PONG
            assert reply.in_reply_to == req.msg_id

    # ---- run() / close() lifecycle ------------------------------------------

    async def test_run_starts_recv_loop_and_serves(self, node: KademliaNode):
        # run() must actually start the recv_loop: a request put on the inbox
        # gets answered without us driving recv_loop() ourselves.
        await node.run()
        try:
            req = make_msg(MsgType.PING, PingPayload())
            await node.socket.inbox_queue.put(("203.0.113.5", req.to_bytes()))

            _, _, reply = await get_reply(node)
            assert reply.msg_type is MsgType.PONG
            assert reply.in_reply_to == req.msg_id
        finally:
            await node.close()

    async def test_close_cancels_recv_loop(self, node: KademliaNode):
        # close() must tear the background recv_loop down.
        await node.run()
        recv_task = node.get_named_closable(KademliaNode.recv_loop.__name__)
        assert isinstance(recv_task, asyncio.Task) and not recv_task.done()

        await node.close()
        assert recv_task.done()

    # ---- end-to-end: two real nodes over a fake network ---------------------

    async def test_e2e_ping_succeeds(self, network: FakeNetwork):
        a = network.add_node("10.0.0.1", build_node())
        network.add_node("10.0.0.2", build_node())
        assert await a.ping("10.0.0.2") is True

    async def test_e2e_ping_unknown_host_times_out(self, network: FakeNetwork):
        a = network.add_node("10.0.0.1", build_node())
        # Nobody at this address -> no PONG -> timeout -> False.
        assert await a.ping("10.0.0.250", timeout=0.05) is False

    async def test_e2e_store_replicates_to_peer(self, network: FakeNetwork):
        a = network.add_node("10.0.0.1", build_node())
        b = network.add_node("10.0.0.2", build_node())
        value = os.urandom(64)

        # The value does reach b's DHT, but the ack never correlates back.
        assert await a.store_req("10.0.0.2", value) is True
        assert b.dht[hashlib.sha256(value).digest()] == value

    async def test_e2e_find_node_returns_peers_neighbors(self, network: FakeNetwork):
        a = network.add_node("10.0.0.1", build_node())
        b = network.add_node("10.0.0.2", build_node())
        b.peers = [Peer(node_id=os.urandom(32), ip="9.9.9.9")]

        result = await a.find_node_req("10.0.0.2", target=os.urandom(32))
        assert result == b.peers

    async def test_e2e_find_value_hit_returns_value(self, network: FakeNetwork):
        a = network.add_node("10.0.0.1", build_node())
        b = network.add_node("10.0.0.2", build_node())
        value = os.urandom(30)
        key = os.urandom(32)
        b.dht[key] = value

        reply = await a.find_value_req("10.0.0.2", key=key)
        assert reply is not None
        assert reply.value == value
