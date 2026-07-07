from datetime import datetime
from functools import lru_cache
import uuid, hashlib, logging, asyncio
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Self
from nacl.exceptions import CryptoError
from pydantic import BaseModel, Field, SerializeAsAny, model_validator
from encryption import EncryptedMsg, PeerEncryption, Signature, UserEncryption
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from closable import Closable
from handlers import HandlerBase
from socket_handler import AnySocketHandler, SocketHandler
from .types import B64Bytes, ContentType, KademliaKey
import secrets

logger = logging.getLogger(__name__)

# Network-wide well-known port.
KADEMLIA_PORT = 9009
ID_SPACE = 256 # bit
ALPHA = 3


def kademlia_key(data: bytes) -> KademliaKey:
    return KademliaKey(hashlib.sha256(data).digest())


class MsgType(str, Enum):
    PING = "PING"
    PONG = "PONG"
    STORE = "STORE"
    STORE_REPLY = "STORE_REPLY"
    FIND_NODE = "FIND_NODE"
    FIND_NODE_REPLY = "FIND_NODE_REPLY"
    FIND_VALUE = "FIND_VALUE"
    FIND_VALUE_REPLY = "FIND_VALUE_REPLY"
    CHAT_MSG = "CHAT_MSG"
    CHAT_MSG_REPLY = "CHAT_MSG_REPLY"


class Peer(BaseModel):
    id: KademliaKey
    ip: str
    pubkey: B64Bytes
    
def invent_peer(ip: str) -> Peer:
    enc = UserEncryption.create()
    return Peer(id=enc.id, ip=ip, pubkey=enc.public_bytes)


BOOTSTRAP_PEERS = [invent_peer("127.0.0.1"), invent_peer("127.0.0.2")]

BOOTSTRAP_LOOKUPS = 5


class Payload(BaseModel):
    """Base class for all payloads."""
    pass


class PingPayload(Payload):
    pass


class PongPayload(Payload):
    pass


class StorePayload(Payload):
    key: B64Bytes
    value: B64Bytes


class StoreReplyPayload(Payload):
    success: bool


class FindNodePayload(Payload):
    target: KademliaKey  # node ID being searched for


class FindNodeReplyPayload(Payload):
    nodes: list[Peer] = Field(default_factory=list)


class FindValuePayload(Payload):
    key: KademliaKey


class FindValueReplyPayload(Payload):
    # Either the value was found ...
    value: B64Bytes | None = None
    # ... or the k closest contacts are returned.
    nodes: list[Peer] = Field(default_factory=list)

class ChatMsgPayload(Payload):
    chat_id: B64Bytes = Field(min_length=16, max_length=16) # uuid4
    shared_secret: B64Bytes = Field(min_length=32, max_length=32) # 256 Bit
    message: B64Bytes
    content_type: ContentType
    timestamp: datetime


class ChatMsgReplyPayload(Payload):
    success: bool


# Registry: msg_type -> payload
PAYLOAD_TYPES: dict[MsgType, type[Payload]] = {
    MsgType.PING: PingPayload,
    MsgType.PONG: PongPayload,
    MsgType.STORE: StorePayload,
    MsgType.STORE_REPLY: StoreReplyPayload,
    MsgType.FIND_NODE: FindNodePayload,
    MsgType.FIND_NODE_REPLY: FindNodeReplyPayload,
    MsgType.FIND_VALUE: FindValuePayload,
    MsgType.FIND_VALUE_REPLY: FindValueReplyPayload,
    MsgType.CHAT_MSG: ChatMsgPayload,
    MsgType.CHAT_MSG_REPLY: ChatMsgReplyPayload,
}

# Expected reply msg type for a given request msg type
REPLY_TYPES: dict[MsgType, MsgType] = {
    MsgType.PING: MsgType.PONG,
    MsgType.STORE: MsgType.STORE_REPLY,
    MsgType.FIND_NODE: MsgType.FIND_NODE_REPLY,
    MsgType.FIND_VALUE: MsgType.FIND_VALUE_REPLY,
    MsgType.CHAT_MSG: MsgType.CHAT_MSG_REPLY,
}


type MsgId = B64Bytes


class KademliaMsg(BaseModel):
    msg_type: MsgType
    msg_id: MsgId = Field(default_factory=lambda: uuid.uuid4().bytes)
    in_reply_to: MsgId | None = None # reference the msg_id of the request
    sender_id: B64Bytes      # node ID = sha256(pubkey)
    sender_pubkey: B64Bytes  # raw public key
    signature: B64Bytes
    payload: SerializeAsAny[Payload]

    @model_validator(mode="before")
    @classmethod
    def _coerce_payload(cls, data):
        """Upgrade a payload dict into the right class based on msg_type."""
        if isinstance(data, dict):
            payload = data.get("payload")
            msg_type = data.get("msg_type")
            if isinstance(payload, dict) and msg_type is not None:
                model = PAYLOAD_TYPES[MsgType(msg_type)]
                data = {**data, "payload": model.model_validate(payload)}
        return data

    @model_validator(mode="after")
    def _verify_sender_id(self) -> Self:
        expected = hashlib.sha256(self.sender_pubkey).digest()  # always 32 bytes
        if self.sender_id != expected:
            raise ValueError("sender_id is not sha256(sender_pubkey)")
        return self

    @model_validator(mode="after")
    def _verify_payload_type(self) -> Self:
        expected = PAYLOAD_TYPES[self.msg_type]
        if not isinstance(self.payload, expected):
            raise ValueError(
                f"payload type {type(self.payload).__name__} does not match "
                f"msg_type {self.msg_type.value} (expected {expected.__name__})"
            )
        return self

    def verify_signature(self) -> None:
        enc = PeerEncryption.from_peer(id=KademliaKey(self.sender_id), public_bytes=self.sender_pubkey)

        # get the signature of the message, but it has to be made without the signature itself, so extract that first
        signature = self.signature
        try:
            self.signature = b""
            data = self.to_bytes()
        finally:
            self.signature = signature

        # then verify (raises on error)
        enc.verify(signature=Signature(signature), message=data)

    def to_bytes(self) -> bytes:
        return self.model_dump_json().encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        return cls.model_validate_json(data)


def byte_xor(a: bytes, b: bytes) -> bytes:
    return bytes([_a ^ _b for _a, _b in zip(a, b)])

@dataclass
class Contact:
    peer: Peer
    fail_counter: int = 0
    
    @property
    def ip(self):
        return self.peer.ip

type OnNeedsPing = Callable[[Peer], None]

type Bucket = dict[KademliaKey, Contact]

class Buckets:
    def __init__(self, node_id: KademliaKey, on_needs_ping: OnNeedsPing, k=10) -> None:
        self.node_id = node_id
        self.on_needs_ping = on_needs_ping
        self.k = k
        self.failure_remove_threshold = 3
        self.buckets: dict[int, Bucket] = {}
        self.candidate_cache: dict[int, Bucket] = {}
        for i in range(ID_SPACE):
            self.buckets[i] = {}
            self.candidate_cache[i] = {}

    def _determine_bucket(self, peer_id: KademliaKey) -> int:
        distance = int.from_bytes(byte_xor(self.node_id, peer_id))
        if distance == 0:
            raise ValueError(f"Peer-id {peer_id!r} is identical to this node's ID")
        return distance.bit_length() - 1

    def _bucket_for(self, peer_id: KademliaKey) -> Bucket:
        return self.buckets[self._determine_bucket(peer_id)]

    def _cache_for(self, peer_id: KademliaKey) -> Bucket:
        return self.candidate_cache[self._determine_bucket(peer_id)]

    def _remove_oldest_dict_entry(self, d: dict) -> None:
        if not d:
            return
        del d[next(iter(d))] # first entry is the oldest

    def _move_dict_entry_to_tail(self, d: dict, key: Any) -> None:
        '''Raises KeyError when key does not exist'''
        d[key] = d.pop(key)

    def _all_entries_in_buckets(self):
        return [e for bucket in self.buckets.values() for e in bucket.items()]

    def _add_peer(self, peer: Peer) -> None:
        bucket = self._bucket_for(peer.id)
        if len(bucket) >= self.k:
            raise RuntimeError(f"Bucket for peer {peer.id!r} reached maximum entries")
        bucket[peer.id] = Contact(peer)

    def _cache_peer(self, peer: Peer) -> None:
        cache = self._cache_for(peer.id)
        if peer.id in cache:
            self._move_dict_entry_to_tail(cache, peer.id)
            return
        if len(cache) >= self.k:
            self._remove_oldest_dict_entry(cache)
        cache[peer.id] = Contact(peer)

    def _mark_alive(self, peer_id: KademliaKey) -> None:
        bucket = self._bucket_for(peer_id)
        try:
            self._move_dict_entry_to_tail(bucket, peer_id)
        except KeyError:
            raise ValueError(f"Peer-id {peer_id!r} is not present in its bucket")
        bucket[peer_id].fail_counter = 0

    def _ping_next_candidate(self, bucket_id: int) -> None:
        cache = self.candidate_cache[bucket_id]
        if not cache:
            return
        next_candidate_id = next(reversed(cache))
        self.on_needs_ping(cache[next_candidate_id].peer)

    def register_failure(self, peer_id: KademliaKey) -> None:
        bucket = self._bucket_for(peer_id)
        cache = self._cache_for(peer_id)
        bucket_id = self._determine_bucket(peer_id)

        if peer_id in cache:
            del cache[peer_id]
            self._ping_next_candidate(bucket_id)
            return

        if peer_id in bucket:
            bucket[peer_id].fail_counter += 1

            if bucket[peer_id].fail_counter >= self.failure_remove_threshold:
                bucket.pop(peer_id)
                self._ping_next_candidate(bucket_id)

    def register_successful_contact(self, peer: Peer):
        peer_id = peer.id
        bucket = self._bucket_for(peer_id)

        if peer_id in bucket:
            self._mark_alive(peer_id)
        elif len(bucket) < self.k:
            self._add_peer(peer)
            # remove peer from cache in case it was cached before
            self._cache_for(peer_id).pop(peer_id, None)
        else:
            self._cache_peer(peer)

    def get_k_nearest_neighbors(self, target_id: KademliaKey) -> list[Peer]:
        def by_distance(item: tuple[bytes, Contact]):
            return byte_xor(item[0], target_id)

        k_neighbors = sorted(self._all_entries_in_buckets(), key=by_distance)[:self.k]
        return [c.peer for _, c in k_neighbors]

    def get_peer(self, peer_id: KademliaKey) -> Peer | None:
        bucket = self._bucket_for(peer_id)
        if peer_id not in bucket:
            return None
        return bucket[peer_id].peer


@dataclass
class _Pending:
    """An outstanding request awaiting its reply."""
    future: asyncio.Future[KademliaMsg]
    peer_ip: str
    reply_type: MsgType


class Handler(HandlerBase):
    async def chat_msg_received(self, sender: Peer, payload: ChatMsgPayload):
        pass


class KademliaNode(Closable):
    """Provides Kademlia logic and RPCs. Communicates via SocketHandler
    inbox and outbox queues. Automatically handles incoming requests and
    populates k-Buckets when started.
    """

    def __init__(self, socket: AnySocketHandler, node_id: KademliaKey, pubkey: bytes, encryption: UserEncryption, handler: Handler, port: int = KADEMLIA_PORT) -> None:
        super().__init__()
        self.socket = socket
        self.node_id = node_id
        self.pubkey = pubkey
        self.port = port
        self.encryption = encryption
        self.buckets = Buckets(node_id, self._ping_with_buckets_side_effect)
        self.loop = asyncio.get_running_loop()
        self.dht: dict[bytes, Any] = {} # TODO: store this in a more appropriate way
        self.handler = handler
        # Outstanding requests awaiting a reply, keyed by the request's msg_id.
        self._pending_by_msg_id: dict[MsgId, _Pending] = {}
        
    @property
    def peer(self) -> Peer:
        return Peer(id=self.node_id, ip=self.socket.ip, pubkey=self.encryption.public_bytes)

    async def resolve_peer(self, target: KademliaKey) -> Peer:
        if target == self.node_id:
            raise ValueError("Cannot resolve own node ID")
        if peer := self.buckets.get_peer(target):
            return peer
        peers = await self.find_node(target)
        resolved = next((p for p in peers if p.id == target), None)
        if resolved is None:
            raise RuntimeError(f"Failed to resolve peer ID: {target}")
        return resolved

    async def join_network(self) -> None:
        #Register bootstrap peers
        for peer in BOOTSTRAP_PEERS:
            if peer.id == self.node_id:
                continue
            self.buckets.register_successful_contact(peer)
        #Lookup own id
        await self.find_node(self.node_id)
        #Repeat N times
        for _ in range (BOOTSTRAP_LOOKUPS):
            # Generate random id
            random_node = secrets.token_bytes(32)
            #Lookup random id
            await self.find_node(KademliaKey(random_node))


    # ---- message plumbing ----------------------------------------------------

    def _new_msg(self, msg_type: MsgType, payload: Payload, in_reply_to: MsgId | None = None) -> KademliaMsg:
        """Wrap a payload into a KademliaMsg signed with our identity."""
        msg = KademliaMsg(
            msg_type=msg_type,
            in_reply_to=in_reply_to,
            sender_id=self.node_id,
            sender_pubkey=self.pubkey,
            signature=b"",
            payload=payload,
        )

        msg.signature = self.encryption.sign(msg.to_bytes())
        return msg

    async def _send(self, dest: Peer, msg: KademliaMsg) -> None:
        """Fire-and-forget primitive: hand a message to the socket outbox."""
        encr = PeerEncryption.from_peer(id=KademliaKey(dest.id), public_bytes=dest.pubkey)
        msg_bytes = msg.to_bytes()
        msg_bytes_encr = self.encryption.encrypt(msg=msg_bytes, receiver=encr)
        await self.socket.outbox_queue.put((dest.ip, KADEMLIA_PORT, msg_bytes_encr))

    async def request(self, *, msg: KademliaMsg, peer: Peer | KademliaKey, timeout: float = 5.0) -> KademliaMsg:
        """
        Send `msg` and wait for the reply (in_reply_tp == msg.msg_id).
        Raises `asyncio.TimeoutError` if no reply comes within `timeout` seconds.
        Provide `peer_id` when possible so timeouts can be registered in `Buckets`
        (so offline/ unresponsive peers can be removed from Buckets)
        """
        if isinstance(peer, bytes):
            peer = await self.resolve_peer(peer)

        fut: asyncio.Future[KademliaMsg] = self.loop.create_future()
        self._pending_by_msg_id[msg.msg_id] = _Pending(fut, peer.ip, REPLY_TYPES[msg.msg_type])
        try:
            await self._send(peer, msg)
            return await asyncio.wait_for(fut, timeout)
        except TimeoutError as e:
            self.buckets.register_failure(peer.id)
            raise e
        finally:
            # Always drop the registration, also on timeout/cancellation.
            self._pending_by_msg_id.pop(msg.msg_id, None)

    # ---- RPCs ----------------------------------------------------------------

    async def ping(self, peer_id: KademliaKey, timeout: float = 5.0) -> bool:
        """Send a PING and wait for the PONG. True if it arrives in time."""
        msg = self._new_msg(MsgType.PING, PingPayload())
        try:
            await self.request(msg=msg, peer=peer_id, timeout=timeout)
            return True
        except (asyncio.TimeoutError, RuntimeError):
            return False

    async def get_peer_infos(self, peer_id: KademliaKey, timeout: float = 5.0) -> Peer:
        """
        Returns the most up-to-date info about a peer (by contacting directly)
        Raises `asyncio.TimeoutError` if the peer does not answer in time.
        Raises `RuntimeError` if the responder's identity differs from `peer_id`.
        """
        peer = await self.resolve_peer(peer_id)
        msg = self._new_msg(MsgType.PING, PingPayload())
        reply = await self.request(msg=msg, peer=peer, timeout=timeout)
        if reply.sender_id != peer_id:
            raise RuntimeError("Response's sender identity does not match the requested peer ID")
        
        return Peer(id=KademliaKey(reply.sender_id), ip=peer.ip, pubkey=reply.sender_pubkey)

    async def _pong(self, peer: Peer, in_reply_to: MsgId) -> None:
        """Fire-and-forget reply to a PING."""
        await self._send(peer, self._new_msg(MsgType.PONG, PongPayload(), in_reply_to))

    def _ping_with_buckets_side_effect(self, peer: Peer) -> None:
        """
        Sync ping callback for Buckets. Will be called for peers that may not be in
        a bucket yet, but IP is known. Calls `request` with both peer_id and dest_ip so `request`
        is able to register failed contact for Buckets.
        """
        async def _ping():
            msg = self._new_msg(MsgType.PING, PingPayload())
            await self.request(msg=msg, peer=peer)

        self.bind_closable(_ping())

    async def find_node(self, target: KademliaKey) -> list[Peer]:
        from .lookup import NodeLookup
        return await NodeLookup(self, target).run()

    async def _find_node_req(self, target: KademliaKey, peer: Peer, timeout: float = 5.0) -> list[Peer] | None:
        """
        Send a FIND_NODE request and wait for the reply. Returns `list[Peer]` if reply
        arrives on time, `None` otherwise.
        Provide `peer_id` if possibel, so `request` can register possible failures in Buckets.
        """
        msg = self._new_msg(
            msg_type=MsgType.FIND_NODE,
            payload=FindNodePayload(target=target),
        )
        try:
            reply = await self.request(peer=peer, msg=msg, timeout=timeout)
        except asyncio.TimeoutError:
            return None
        assert isinstance(reply.payload, FindNodeReplyPayload)
        return reply.payload.nodes

    async def _find_node_reply(self, peer: Peer, in_reply_to: MsgId, target: KademliaKey) -> None:
        """Fire-and-foreget reply to FIND_NODE"""
        msg = self._new_msg(
            msg_type=MsgType.FIND_NODE_REPLY,
            payload=FindNodeReplyPayload(
                nodes=self.buckets.get_k_nearest_neighbors(target)
            ),
            in_reply_to=in_reply_to
        )
        await self._send(peer, msg)

    async def find_value(self, key: KademliaKey) -> bytes:
        from .lookup import ValueLookup
        return await ValueLookup(self, key).run()


    async def _find_value_req(self, peer: Peer, key: KademliaKey, timeout: float = 5.0) -> None | FindValueReplyPayload:
        """
        Send a FIND_VALUE request. Returns `None` on timeout, `FindValueReplyPayload` otherwise.
        """
        msg = self._new_msg(
            msg_type=MsgType.FIND_VALUE,
            payload=FindValuePayload(key=key),
        )
        try:
            reply = await self.request(peer=peer, msg=msg, timeout=timeout)
        except asyncio.TimeoutError:
            return None
        assert isinstance(reply.payload, FindValueReplyPayload)
        return reply.payload

    async def _find_value_reply(self, peer: Peer, in_reply_to: MsgId, value: bytes | None = None, neighbors: list[Peer] | None = None) -> None:
        """Fire-and-forget reply to FIND_VALUE"""
        if value is None and neighbors is None:
            raise ValueError("Either value or neighbors must be given as an argument.")
        if value is not None:
            payload = FindValueReplyPayload(value=value)
        else:
            assert neighbors is not None
            payload = FindValueReplyPayload(nodes=neighbors)

        msg = self._new_msg(
            msg_type=MsgType.FIND_VALUE_REPLY,
            payload=payload,
            in_reply_to=in_reply_to
        )
        await self._send(peer, msg)

    async def store_req(self, peer: Peer, value: bytes, timeout: float = 5.0) -> bool:
        """
        Send a STORE request. Returns `False` on timeout or failure,
        returns `True` on success.
        """
        key = hashlib.sha256(value).digest()
        msg = self._new_msg(
            msg_type=MsgType.STORE,
            payload=StorePayload(key=key, value=value)
        )
        try:
            reply = await self.request(peer=peer, msg=msg, timeout=timeout)
        except asyncio.TimeoutError:
            return False
        assert isinstance(reply.payload, StoreReplyPayload)
        return reply.payload.success

    async def _store_reply(self, peer: Peer, in_reply_to: MsgId, success: bool) -> None:
        """Fire-and-forget reply to STORE"""
        msg = self._new_msg(
            msg_type=MsgType.STORE_REPLY,
            payload=StoreReplyPayload(success=success),
            in_reply_to=in_reply_to
        )
        await self._send(peer, msg)

    async def chat_msg_req(self, peer_id: KademliaKey, chat_id: bytes, shared_secret: bytes, message: bytes,
                           content_type: ContentType, timestamp: datetime, timeout: float = 5.0) -> bool:
        """
        Sends an application level CHAT MESSAGE. Returns 'True' if the recipient acknowledges it before timeout,
        'False' otherwise
        """
        peer = await self.resolve_peer(peer_id)

        msg = self._new_msg(
            msg_type=MsgType.CHAT_MSG,
            payload=ChatMsgPayload(
                chat_id=chat_id,
                shared_secret=shared_secret,
                message=message,
                content_type=content_type,
                timestamp=timestamp
            ),
        )

        try:
            reply = await self.request(peer=peer, msg=msg, timeout=timeout)
        except asyncio.TimeoutError:
            return False

        assert isinstance(reply.payload, ChatMsgReplyPayload)
        return reply.payload.success

    async def _chat_msg_reply(self, peer: Peer, in_reply_to: MsgId, success: bool) -> None :
        """
        Fire-and-forget reply to CHAT_MSG
        """
        msg = self._new_msg(
            msg_type=MsgType.CHAT_MSG_REPLY,
            payload=ChatMsgReplyPayload(success = success),
            in_reply_to = in_reply_to
        )
        await self._send(peer, msg)



    def _is_valid_reply(self, sender_ip: str, msg: KademliaMsg) -> bool:
        if not msg.in_reply_to:
            return False
        
        pending = self._pending_by_msg_id.get(msg.in_reply_to)
        if pending is None:
            # No one is waiting: late, duplicate, or unwanted reply.
            return False
        # A matching msg_id is not enough: the reply must come from the peer
        # we actually queried and carry the reply type we expect. Otherwise
        # ignore it and keep waiting (a spoofed/wrong reply must not resolve
        # the request) until the real one arrives or the request times out.
        if sender_ip != pending.peer_ip or msg.msg_type is not pending.reply_type:
            logger.warning(
                "Dropping mismatched reply to %s from %s (type=%s; expected %s from %s)",
                msg.in_reply_to.hex(), sender_ip, msg.msg_type.value,
                pending.reply_type.value, pending.peer_ip,
            )
            return False
        return True


    async def handle_msg(self, sender_ip: str, msg: KademliaMsg):
        # Replies are correlated back to whoever is awaiting their request.
        peer = Peer(id=KademliaKey(msg.sender_id), ip=sender_ip, pubkey=msg.sender_pubkey)
        
        if msg.in_reply_to is not None:
            if not self._is_valid_reply(sender_ip, msg):
                return
            pending = self._pending_by_msg_id.get(msg.in_reply_to)
            assert pending # _is_valid_reply ensures pending is not None
            if not pending.future.done():
                pending.future.set_result(msg)
            self.buckets.register_successful_contact(peer)
            return

        # Requests:
        if msg.msg_type is MsgType.PING:
            await self._pong(peer=peer, in_reply_to=msg.msg_id)
        elif msg.msg_type is MsgType.FIND_NODE:
            assert isinstance(msg.payload, FindNodePayload)
            await self._find_node_reply(
                peer=peer,
                in_reply_to=msg.msg_id,
                target=msg.payload.target
            )
        elif msg.msg_type is MsgType.STORE:
            assert isinstance(msg.payload, StorePayload)
            self.dht[msg.payload.key] = msg.payload.value
            await self._store_reply(
                peer=peer,
                in_reply_to=msg.msg_id,
                success=True
            )
        elif msg.msg_type is MsgType.FIND_VALUE:
            assert isinstance(msg.payload, FindValuePayload)
            # value exists in local dht => send the value
            if msg.payload.key in self.dht:
                await self._find_value_reply(
                    peer=peer,
                    in_reply_to=msg.msg_id,
                    value=self.dht[msg.payload.key]
                )
            # value doesn't exist in local dht => send k-nearest neigbors
            else:
                await self._find_value_reply(
                    peer=peer,
                    in_reply_to=msg.msg_id,
                    neighbors=self.buckets.get_k_nearest_neighbors(msg.payload.key)
                )
        elif msg.msg_type is MsgType.CHAT_MSG:
            assert isinstance(msg.payload, ChatMsgPayload)

            logger.debug(
                "Received chat message from %s: %s",
                sender_ip,
                msg.payload.message
            )
            try:
                await self.handler.chat_msg_received(
                    sender=peer,
                    payload=msg.payload
                )
            except Exception: # Spoofed ChatID, wrong secret, ...
                success = False
            else:
                success = True

            await self._chat_msg_reply(
                peer=peer,
                in_reply_to=msg.msg_id,
                success=success
            )


        else:
            logger.debug(f"Received message with unknown msg_type: {msg}")
            return
        self.buckets.register_successful_contact(peer)


    async def recv_loop(self):
        while True:
            inbox_item = await self.socket.inbox_queue.get()
            sender_ip = inbox_item[0]
            raw_msg_encr = EncryptedMsg(inbox_item[1])
            
            try:
                raw_msg = self.encryption.decrypt(raw_msg_encr)
                parsed = KademliaMsg.from_bytes(raw_msg)
                parsed.verify_signature()
            except ValueError as e:
                # Malformed / unverifiable message (bad JSON,
                # payload/type mismatch, ...). Drop it and keep serving.
                logger.warning(f"Discarding invalid message from {sender_ip}", sender_ip, exc_info=e)
                continue
            except CryptoError as e:
                logger.warning(f"Decryption error for message from {sender_ip}", sender_ip, exc_info=e)
                continue
            except InvalidSignature as e:
                logger.warning(f"Message from {sender_ip} has invalid signature", sender_ip, exc_info=e)
                continue
            
            logger.debug(f"Received {parsed.msg_type.value} from {sender_ip}")
            await self.handle_msg(sender_ip, parsed)

    async def run(self):
        logger.info("Kademlia node %s listening on port %d", self.node_id.hex()[:8], self.port)
        self.bind_named_closable(self.recv_loop.__name__, asyncio.create_task(self.recv_loop()))
        await self.join_network()
