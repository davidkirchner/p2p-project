import os
import asyncio
import hashlib
import contextlib

import pytest
from typing import Any
from uuid import uuid4
from unittest.mock import AsyncMock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from kademlia.kademlia import (
    Buckets,
    ID_SPACE,
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
from socket_handler import SocketHandler

# The tests drive a node purely through the SocketHandler's two queues and never
# start its networking, so the real SocketHandler can be used as-is: instantiating
# it only sets up the (empty) inbox/outbox queues, without binding any socket.

# Schlüsselpaar erzeugen
priv = Ed25519PrivateKey.generate()
pub = priv.public_key()

# Public Key als rohe 32 Bytes
pub_raw = pub.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
sender_id = hashlib.sha256(pub_raw).digest()


def make_msg(msg_type: MsgType, payload: Payload | dict, **overrides) -> KademliaMsg:
    kwargs: dict[str, Any] = dict(
        msg_type=msg_type,
        msg_id=uuid4().bytes,
        sender_id=sender_id,
        sender_pubkey=pub_raw,
        payload=payload,
        # Built with an empty signature (verification is skipped for it) so we
        # can sign the serialized message below, exactly as _new_msg() does.
        signature=b"",
    )
    kwargs.update(overrides)
    msg = KademliaMsg(**kwargs)
    if "signature" not in overrides:
        msg.signature = priv.sign(msg.to_bytes())
    return msg



def test_empty_dict_payload_is_coerced():
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
                nodes=[Peer(id=os.urandom(32), ip="10.0.0.1")]
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
                nodes=[Peer(id=os.urandom(32), ip="10.0.0.2")]
            ),
        ),
    ],
)
def test_payload_roundtrip(msg_type: MsgType, payload: Payload):
    msg = make_msg(msg_type, payload, in_reply_to=uuid4().bytes)
    parsed = KademliaMsg.from_bytes(msg.to_bytes())
    assert parsed == msg
    assert type(parsed.payload) is type(payload)






# =============================================================================
# Buckets tests
# =============================================================================

# create an all-zero node_id, so a peer's XOR distance to it is just the
# integer value of its own id.
NODE_ID = bytes(ID_SPACE // 8)  # 32 zero bytes


def peer_id_at(distance: int) -> bytes:
    """A peer id whose XOR distance to the all-zero NODE_ID is ``distance``."""
    return distance.to_bytes(ID_SPACE // 8, "big")


def generate_contact_ids(bucket_index: int, count: int) -> list[bytes]:
    first_distance = 1 << bucket_index
    return [peer_id_at(first_distance + i) for i in range(count)]


def make_buckets(k: int = 10) -> tuple[Buckets, list[str]]:
    """A Buckets instance plus the list its on_needs_ping callback appends to."""
    pinged: list[str] = []
    return Buckets(NODE_ID, pinged.append, k=k), pinged


class TestBuckets:
    # ---- bucket placement ----------------------------------------------------

    def test_determine_bucket_uses_xor_distance_bit_length(self):
        buckets, _ = make_buckets()
        # distance 1 -> bit_length 1 -> bucket 0; distance 128 -> bucket 7.
        assert buckets._determine_bucket(peer_id_at(1)) == 0
        assert buckets._determine_bucket(peer_id_at(2)) == 1
        assert buckets._determine_bucket(peer_id_at(3)) == 1
        assert buckets._determine_bucket(peer_id_at(128)) == 7

    def test_determine_bucket_rejects_own_id(self):
        buckets, _ = make_buckets()
        with pytest.raises(ValueError):
            buckets._determine_bucket(NODE_ID)

    # ---- register_successful_contact: add / lookup ---------------------------

    def test_successful_contact_adds_new_peer(self):
        buckets, _ = make_buckets()
        peer_id = peer_id_at(5)
        buckets.register_successful_contact(peer_id, "10.0.0.5")
        assert buckets.get_peer(peer_id) == Peer(id=peer_id, ip="10.0.0.5")

    def test_get_peer_returns_none_for_unknown(self):
        buckets, _ = make_buckets()
        assert buckets.get_peer(peer_id_at(42)) is None

    def test_successful_contact_for_known_peer_resets_failures(self):
        buckets, _ = make_buckets()
        peer_id = peer_id_at(5)
        buckets.register_successful_contact(peer_id, "10.0.0.5")
        buckets.register_failure(peer_id)
        assert buckets._bucket_for(peer_id)[peer_id].fail_counter == 1

        # Seeing the peer again must clear its accumulated failures.
        buckets.register_successful_contact(peer_id, "10.0.0.5")
        assert buckets._bucket_for(peer_id)[peer_id].fail_counter == 0

    def test_mark_alive_moves_peer_to_tail(self):
        buckets, _ = make_buckets()
        ids = generate_contact_ids(7, 3)
        for i, peer_id in enumerate(ids):
            buckets.register_successful_contact(peer_id, f"10.0.0.{i}")

        # Touch the first-inserted peer; it should become the most-recent (tail).
        buckets.register_successful_contact(ids[0], "10.0.0.0")
        order = list(buckets._bucket_for(ids[0]).keys())
        assert order[-1] == ids[0]
        assert buckets._bucket_for(ids[0])[ids[0]].ip == "10.0.0.0"

    # ---- bucket-full handling / candidate cache ------------------------------

    def test_full_bucket_diverts_new_peer_to_cache(self):
        buckets, _ = make_buckets(k=2)
        a, b, c = generate_contact_ids(7, 3)
        buckets.register_successful_contact(a, "10.0.0.1")
        buckets.register_successful_contact(b, "10.0.0.2")
        # Bucket is now full (k=2); the third peer must not enter the bucket.
        buckets.register_successful_contact(c, "10.0.0.3")
        cache = buckets._cache_for(c)

        assert buckets.get_peer(c) is None
        assert len(cache) == 1
        assert c in cache

    def test_cache_evicts_oldest_when_full(self):
        buckets, _ = make_buckets(k=2)
        a, b, c, d, e = generate_contact_ids(7, 5)
        # Fill the bucket, then overflow the cache (also size k=2).
        buckets.register_successful_contact(a, "10.0.0.1")
        buckets.register_successful_contact(b, "10.0.0.2")
        buckets.register_successful_contact(c, "10.0.0.3")  # cached (oldest)
        buckets.register_successful_contact(d, "10.0.0.4")  # cached
        buckets.register_successful_contact(e, "10.0.0.5")  # evicts c

        cache = buckets._cache_for(a)
        assert c not in cache
        assert set(cache) == {d, e}

    def test_recaching_known_candidate_refreshes_its_position(self):
        buckets, _ = make_buckets(k=2)
        a, b, c, d = generate_contact_ids(7, 4)
        buckets.register_successful_contact(a, "10.0.0.1")
        buckets.register_successful_contact(b, "10.0.0.2")
        buckets.register_successful_contact(c, "10.0.0.3")  # cached (oldest)
        buckets.register_successful_contact(d, "10.0.0.4")  # cached
        # Re-seeing c moves it to the tail, so d is now the oldest.
        buckets.register_successful_contact(c, "10.0.0.3")

        assert list(buckets._cache_for(a)) == [d, c]

    def test_promoting_to_bucket_drops_stale_cache_entry(self):
        buckets, _ = make_buckets(k=2)
        a, b, c = generate_contact_ids(7, 3)
        buckets.register_successful_contact(a, "10.0.0.1")
        buckets.register_successful_contact(b, "10.0.0.2")
        buckets.register_successful_contact(c, "10.0.0.3")  # cached
        assert c in buckets._cache_for(c)

        # failure of peer in bucket
        for _ in range(buckets.failure_remove_threshold):
            buckets.register_failure(a)

        buckets.register_successful_contact(c, "10.0.0.3")
        # cached peer should have replaced failed peer
        assert buckets.get_peer(c) == Peer(id=c, ip="10.0.0.3")
        # and be removed from the cache
        assert c not in buckets._cache_for(c)

    def test_unresponsive_candidate_is_dropped_and_next_alive_is_promoted(self):
        buckets, pings = make_buckets(k=2)
        a, b, c, d = generate_contact_ids(7, 4)
        bucket, cache = buckets.buckets[7], buckets.candidate_cache[7]
        buckets.register_successful_contact(a, "10.0.0.1")
        buckets.register_successful_contact(b, "10.0.0.2")
        buckets.register_successful_contact(c, "10.0.0.3")  # cached (oldest)
        buckets.register_successful_contact(d, "10.0.0.4")  # cached (will not answer ping on promotion)

        # failure of peer in bucket
        for _ in range(buckets.failure_remove_threshold):
            buckets.register_failure(a)

        assert pings == ["10.0.0.4"]
        buckets.register_failure(d) # doesn't answer ping
        assert d not in cache
        assert d not in bucket

        assert pings == ["10.0.0.4", "10.0.0.3"]
        buckets.register_successful_contact(c, "10.0.0.3")
        assert c not in cache
        assert c in bucket

    # ---- register_failure ----------------------------------------------------

    def test_failure_on_unknown_peer_is_noop(self):
        buckets, pinged = make_buckets()
        buckets.register_failure(peer_id_at(99))  # never seen -> nothing happens
        assert pinged == []

    def test_peer_removed_after_threshold_failures(self):
        buckets, _ = make_buckets()
        peer_id = peer_id_at(5)
        buckets.register_successful_contact(peer_id, "10.0.0.5")
        # peer survives the failures if failures < threshold
        for _ in range(buckets.failure_remove_threshold - 1):
            buckets.register_failure(peer_id)
        assert buckets.get_peer(peer_id) is not None
        # one more failure => threshold reached
        buckets.register_failure(peer_id)
        assert buckets.get_peer(peer_id) is None

    def test_eviction_pings_waiting_candidate(self):
        buckets, pinged = make_buckets(k=2)
        a, b, c = generate_contact_ids(7, 3)
        buckets.register_successful_contact(a, "10.0.0.1")
        buckets.register_successful_contact(b, "10.0.0.2")
        buckets.register_successful_contact(c, "10.0.0.3")  # cached candidate

        for _ in range(buckets.failure_remove_threshold):
            buckets.register_failure(a)  # remove a, freeing a slot

        # The freed slot triggers a ping to the waiting candidate so it can be
        # promoted once it answers.
        assert pinged == ["10.0.0.3"]

    def test_eviction_without_candidate_pings_nothing(self):
        buckets, pinged = make_buckets()
        peer_id = peer_id_at(5)
        buckets.register_successful_contact(peer_id, "10.0.0.5")
        for _ in range(buckets.failure_remove_threshold):
            buckets.register_failure(peer_id)
        assert pinged == []

    # ---- get_k_nearest_neighbors ---------------------------------------------

    def test_knn_empty_when_no_peers(self):
        buckets, _ = make_buckets()
        assert buckets.get_k_nearest_neighbors(peer_id_at(1)) == []

    def test_knn_sorted_by_xor_distance_to_target(self):
        buckets, _ = make_buckets()
        for d in (5, 3, 9, 1, 7):
            buckets.register_successful_contact(peer_id_at(d), f"10.0.0.{d}")

        # Target all-zeros: distance == id
        nearest = buckets.get_k_nearest_neighbors(NODE_ID)
        assert [int.from_bytes(p.id) for p in nearest] == [1, 3, 5, 7, 9]

    def test_knn_caps_at_k(self):
        buckets, _ = make_buckets(k=3)
        for i, peer_id in enumerate(generate_contact_ids(7, 2)):
            buckets.register_successful_contact(peer_id, f"10.0.7.{i}")
        # A couple of peers in another bucket too, to span buckets.
        for i, peer_id in enumerate(generate_contact_ids(20, 2)):
            buckets.register_successful_contact(peer_id, f"10.0.20.{i}")

        neighbors = buckets.get_k_nearest_neighbors(NODE_ID)
        assert len(neighbors) == 3
        assert [x.ip for x in neighbors] == ["10.0.7.0", "10.0.7.1", "10.0.20.0"]



# =============================================================================
# KademliaNode tests
# =============================================================================
#
# A node only touches the network through its SocketHandler's two queues, so the
# tests feed its inbox and read its outbox instead of using real sockets

class _Signer:
    """Minimal stand-in for UserEncryption: KademliaNode only calls .sign()."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)


def new_identity() -> tuple[bytes, bytes, _Signer]:
    """A fresh (node_id, pubkey, signer) triple with node_id == sha256(pubkey).

    """
    private_key = Ed25519PrivateKey.generate()
    pubkey = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(pubkey).digest(), pubkey, _Signer(private_key)


def build_node(*, port: int = KADEMLIA_PORT) -> KademliaNode:
    """Build a KademliaNode with its own mock socket and a valid identity.

    Must be called from within a running event loop (KademliaNode grabs the
    loop in __init__).
    """
    node_id, pubkey, signer = new_identity()
    encryption: Any = signer  # KademliaNode only needs .sign(); see _Signer
    return KademliaNode(SocketHandler(), node_id, pubkey, encryption, port=port)


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
        peer = Peer(id=os.urandom(32), ip="9.9.9.9")
        node.buckets.register_successful_contact(peer.id, peer.ip)
        req = make_msg(MsgType.FIND_NODE, FindNodePayload(target=os.urandom(32)))

        await node.handle_msg("203.0.113.5", req)

        _, _, reply = await get_reply(node)
        assert reply.msg_type is MsgType.FIND_NODE_REPLY
        assert reply.in_reply_to == req.msg_id
        assert isinstance(reply.payload, FindNodeReplyPayload)
        assert reply.payload.nodes == [peer]

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
        peer = Peer(id=os.urandom(32), ip="9.9.9.9")
        node.buckets.register_successful_contact(peer.id, peer.ip)
        req = make_msg(MsgType.FIND_VALUE, FindValuePayload(key=os.urandom(32)))

        await node.handle_msg("203.0.113.5", req)

        _, _, reply = await get_reply(node)
        assert reply.msg_type is MsgType.FIND_VALUE_REPLY
        assert isinstance(reply.payload, FindValueReplyPayload)
        assert reply.payload.value is None
        assert reply.payload.nodes == [peer]

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

        async def _resolve(target: bytes) -> Peer:
            if target == a.node_id:
                return Peer(id=a.node_id, ip="10.0.0.1")
            if target == b.node_id:
                return Peer(id=b.node_id, ip="10.0.0.2")
            raise ValueError

        mocked_resolve_peer = AsyncMock()
        mocked_resolve_peer.side_effect = _resolve

        a.resolve_peer = mocked_resolve_peer
        b.resolve_peer = mocked_resolve_peer

        value = os.urandom(64)

        # The value does reach b's DHT, but the ack never correlates back.
        assert await a.store_req(b.node_id, value) is True
        assert b.dht[hashlib.sha256(value).digest()] == value

    async def test_e2e_find_node_returns_peers_neighbors(self, network: FakeNetwork):
        a = network.add_node("10.0.0.1", build_node())
        b = network.add_node("10.0.0.2", build_node())
        peer = Peer(id=os.urandom(32), ip="9.9.9.9")
        b.buckets.register_successful_contact(peer.id, peer.ip)

        result = await a._find_node_req("10.0.0.2", target=os.urandom(32))
        assert result == [peer]

    async def test_e2e_find_value_hit_returns_value(self, network: FakeNetwork):
        a = network.add_node("10.0.0.1", build_node())
        b = network.add_node("10.0.0.2", build_node())
        value = os.urandom(30)
        key = os.urandom(32)
        b.dht[key] = value

        reply = await a._find_value_req("10.0.0.2", key=key)
        assert reply is not None
        assert reply.value == value
