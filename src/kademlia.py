import uuid, base64, hashlib, logging, asyncio
from dataclasses import dataclass
from enum import Enum
from typing import Annotated, Any, Self
from pydantic import BaseModel, Field, BeforeValidator, PlainSerializer, SerializeAsAny, model_validator
from closable import Closable
from socket_handler import SocketHandler

logger = logging.getLogger(__name__)

# Network-wide well-known port.
KADEMLIA_PORT = 9009

def _b64_decode(v: str | bytes) -> bytes:
    # str   -> from JSON: decode base64 to bytes
    # bytes -> built in code: already raw bytes, pass through
    return base64.b64decode(v) if isinstance(v, str) else v


# Raw bytes in code, base64 on the wire (JSON has no native bytes type).
# Python side stays bytes (model_dump()); only JSON gets the base64 string.
B64Bytes = Annotated[
    bytes,
    # decode: base64 string -> bytes (passthrough if already bytes)
    BeforeValidator(_b64_decode),
    # encode: bytes -> base64 string
    PlainSerializer(
        lambda v: base64.b64encode(v).decode("ascii"),
        return_type=str,
        when_used="json",
    ),
]

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
    node_id: B64Bytes
    ip: str


# ---- Payloads per MessageType ------------------------------------------------
# Each payload model knows only its own fields and handles its binary fields
# itself (via B64Bytes). The transport logic (to_bytes/from_bytes) stays
# generic in KademliaMsg.

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
    target: B64Bytes  # node ID being searched for


class FindNodeReplyPayload(Payload):
    nodes: list[Peer] = Field(default_factory=list)


class FindValuePayload(Payload):
    key: B64Bytes


class FindValueReplyPayload(Payload):
    # Either the value was found ...
    value: B64Bytes | None = None
    # ... or the k closest contacts are returned.
    nodes: list[Peer] = Field(default_factory=list)

class ChatMsgPayload(Payload):
    message: str


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


class KademliaMsg(BaseModel):
    msg_type: MsgType
    msg_id: B64Bytes = Field(default_factory=lambda: uuid.uuid4().bytes)
    in_reply_to: B64Bytes | None = None # reference the msg_id of the request
    sender_id: B64Bytes      # node ID = sha256(pubkey)
    sender_pubkey: B64Bytes  # raw public key
    signature: B64Bytes      # this is not generated/ checked yet
    payload: SerializeAsAny[Payload]  # serialize by runtime type, not by Payload

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

    def to_bytes(self) -> bytes:
        return self.model_dump_json().encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        return cls.model_validate_json(data)


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

@dataclass
class _Pending:
    """An outstanding request awaiting its reply."""
    future: asyncio.Future[KademliaMsg]
    peer_ip: str
    reply_type: MsgType

class KademliaNode(Closable):
    """Kademlia RPC engine sitting on top of the SocketHandler queues.

    Reads incoming messages from ``socket.inbox_queue`` as ``(sender_ip, data)``,
    dispatches by ``msg_type``, and puts replies on ``socket.outbox_queue`` as
    ``(dest_ip, dest_port, data)``.
    """

    def __init__(self, socket: SocketHandler, node_id: bytes, pubkey: bytes, port: int = KADEMLIA_PORT) -> None:
        super().__init__()
        self.socket = socket
        self.node_id = node_id
        self.pubkey = pubkey
        self.port = port
        self.loop = asyncio.get_running_loop()
        self.peers: list[Peer] = []     # TODO: store this in a more appropriate way
        self.dht: dict[bytes, Any] = {} # TODO: store this in a more appropriate way
        # Outstanding requests awaiting a reply, keyed by the request's msg_id.
        self._pending: dict[bytes, _Pending] = {}

    def get_k_nearest_neighbors(self, target: bytes, k: int = 5) -> list[Peer]:
        if len(self.peers) <= k:
            return self.peers

        neighbor_distance_pairs: list[tuple[Peer, bytes]] = [] # (peer, distance)
        for peer in self.peers:
            if len(peer.node_id) != len(target):
                raise ValueError(f"length mismatch of target id ({target.hex()}) and id "
                                 f"of neighbor ({peer.node_id.hex()})")
            distance = byte_xor(peer.node_id, target)
            neighbor_distance_pairs.append((peer, distance))

        # sort by distance
        neighbor_distance_pairs.sort(key=lambda x: x[1])
        # return the k-nearest neighbors
        return [x[0] for x in neighbor_distance_pairs[:k]]


    # ---- message plumbing ----------------------------------------------------

    def _new_msg(self, msg_type: MsgType, payload: Payload, in_reply_to: bytes | None = None) -> KademliaMsg:
        """Wrap a payload into a KademliaMsg signed with our identity."""
        return KademliaMsg(
            msg_type=msg_type,
            in_reply_to=in_reply_to,
            sender_id=self.node_id,
            sender_pubkey=self.pubkey,
            signature=b"dummy-sig",   #add implementation
            payload=payload,
        )

    async def _send(self, dest_ip: str, msg: KademliaMsg) -> None:
        """Fire-and-forget primitive: hand a message to the socket outbox."""
        await self.socket.outbox_queue.put((dest_ip, KADEMLIA_PORT, msg.to_bytes()))

    async def request(self, dest_ip: str, msg: KademliaMsg, timeout: float = 5.0) -> KademliaMsg:
        """Send ``msg`` and wait for the reply whose in_reply_to == msg.msg_id.

        Built on top of the fire-and-forget ``_send``: it registers a future
        before sending, then lets ``recv_loop`` -> ``handle_msg`` resolve it when
        the matching reply arrives. Raises ``asyncio.TimeoutError`` if no reply
        comes within ``timeout`` seconds.
        """
        fut: asyncio.Future[KademliaMsg] = self.loop.create_future()
        self._pending[msg.msg_id] = _Pending(fut, dest_ip, REPLY_TYPES[msg.msg_type])
        try:
            await self._send(dest_ip, msg)
            return await asyncio.wait_for(fut, timeout)
        finally:
            # Always drop the registration, also on timeout/cancellation.
            self._pending.pop(msg.msg_id, None)

    # ---- RPCs ----------------------------------------------------------------

    async def ping(self, dest_ip: str, timeout: float = 5.0) -> bool:
        """Send a PING and wait for the PONG. True if it arrives in time."""
        msg = self._new_msg(MsgType.PING, PingPayload())
        try:
            await self.request(dest_ip, msg, timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def pong(self, dest_ip: str, in_reply_to: bytes) -> None:
        """Fire-and-forget reply to a PING."""
        await self._send(dest_ip, self._new_msg(MsgType.PONG, PongPayload(), in_reply_to=in_reply_to))

    async def find_node_req(self, dest_ip: str, target: bytes, timeout: float = 5.0) -> list[Peer] | None:
        """
        Send a FIND_NODE request and wait for the reply. Returns `list[Peer]` if reply
        arrives on time, `None` otherwise.
        """
        msg = self._new_msg(
            msg_type=MsgType.FIND_NODE,
            payload=FindNodePayload(target=target),
        )
        try:
            reply = await self.request(dest_ip, msg, timeout)
        except asyncio.TimeoutError:
            return None
        assert isinstance(reply.payload, FindNodeReplyPayload)
        return reply.payload.nodes

    async def find_node_reply(self, dest_ip: str, in_reply_to: bytes, target: bytes) -> None:
        """Fire-and-foreget reply to FIND_NODE"""
        msg = self._new_msg(
            msg_type=MsgType.FIND_NODE_REPLY,
            payload=FindNodeReplyPayload(
                nodes=self.get_k_nearest_neighbors(target)
            ),
            in_reply_to=in_reply_to
        )
        await self._send(dest_ip, msg)

    async def find_value_req(self, dest_ip: str, key: bytes, timeout: float = 5.0) -> None | FindValueReplyPayload:
        """
        Send a FIND_VALUE request. Returns `None` on timeout, `FindValueReplyPayload` otherwise.
        """
        msg = self._new_msg(
            msg_type=MsgType.FIND_VALUE,
            payload=FindValuePayload(key=key),
        )
        try:
            reply = await self.request(dest_ip, msg, timeout)
        except asyncio.TimeoutError:
            return None
        assert isinstance(reply.payload, FindValueReplyPayload)
        return reply.payload

    async def find_value_reply(self, dest_ip: str, in_reply_to: bytes, value: bytes | None = None, neighbors: list[Peer] | None = None) -> None:
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
        await self._send(dest_ip, msg)

    async def store_req(self, dest_ip: str, value: bytes, timeout: float = 5.0) -> bool:
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
            reply = await self.request(dest_ip, msg, timeout)
        except asyncio.TimeoutError:
            return False
        assert isinstance(reply.payload, StoreReplyPayload)
        return reply.payload.success

    async def store_reply(self, dest_ip: str, in_reply_to: bytes, success: bool) -> None:
        """Fire-and-forget reply to STORE"""
        msg = self._new_msg(
            msg_type=MsgType.STORE_REPLY,
            payload=StoreReplyPayload(success=success),
            in_reply_to=in_reply_to
        )
        await self._send(dest_ip, msg)

    async def chat_msg_req(self,dest_ip: str,message: bytes,timeout: float = 5.0) -> bool:
        """
        Sends an application level CHAT MESSAGE. Returns 'True' if the recipient acknowledges it before timeout,
        'False' otherwise
        """
        msg = self._new_msg(
            msg_type=MsgType.CHAT_MSG,
            payload=ChatMsgPayload(message=message),
        )

        try:
            reply = await self.request(dest_ip,msg,timeout)
        except asyncio.TimeoutError:
            return False
        
        assert isinstance(reply.payload, ChatMsgReplyPayload)
        return reply.payload.success
    
    async def chat_msg_reply(self, dest_ip: str, in_reply_to: bytes, success: bool) -> None :
        """
        Fire-and-forget reply to CHAT_MSG
        """
        msg = self._new_msg(
            msg_type=MsgType.CHAT_MSG_REPLY,
            payload=ChatMsgReplyPayload(success = success),
            in_reply_to = in_reply_to
        )
        await self._send(dest_ip,msg)


    # ---- dispatch ------------------------------------------------------------

    async def handle_msg(self, sender_ip: str, msg: KademliaMsg):
        # Replies are correlated back to whoever is awaiting their request.
        if msg.in_reply_to is not None:
            pending = self._pending.get(msg.in_reply_to)
            if pending is None:
                # No one is waiting: late, duplicate, or unsolicited reply.
                return
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
                return
            if not pending.future.done():
                pending.future.set_result(msg)
            return

        # Requests:
        if msg.msg_type is MsgType.PING:
            await self.pong(dest_ip=sender_ip, in_reply_to=msg.msg_id)
        elif msg.msg_type is MsgType.FIND_NODE:
            assert isinstance(msg.payload, FindNodePayload)
            await self.find_node_reply(
                dest_ip=sender_ip,
                in_reply_to=msg.msg_id,
                target=msg.payload.target
            )
        elif msg.msg_type is MsgType.STORE:
            assert isinstance(msg.payload, StorePayload)
            self.dht[msg.payload.key] = msg.payload.value
            await self.store_reply(
                dest_ip=sender_ip,
                in_reply_to=msg.msg_id,
                success=True
            )
        elif msg.msg_type is MsgType.FIND_VALUE:
            assert isinstance(msg.payload, FindValuePayload)
            # value exists in local dht => send the value
            if msg.payload.key in self.dht:
                await self.find_value_reply(
                    dest_ip=sender_ip,
                    in_reply_to=msg.msg_id,
                    value=self.dht[msg.payload.key]
                )
            # value doesn't exist in local dht => send k-nearest neigbors
            else:
                await self.find_value_reply(
                    dest_ip=sender_ip,
                    in_reply_to=msg.msg_id,
                    neighbors=self.get_k_nearest_neighbors(msg.payload.key)
                )
        elif msg.msg_type is MsgType.CHAT_MSG:
            assert isinstance(msg.payload, ChatMsgPayload)
            # TODO: Forward the message to the application/UI layer.
            logger.debug(
                "Received chat message from %s: %s",
                sender_ip,
                msg.payload.message
            )
            await self.chat_msg_reply(
                dest_ip=sender_ip,
                in_reply_to=msg.msg_id,
                success=True
            )


    async def recv_loop(self):
        while True:
            sender_ip, raw_msg = await self.socket.inbox_queue.get()
            try:
                parsed = KademliaMsg.from_bytes(raw_msg)
            except ValueError as e:
                # Malformed / unverifiable message (bad JSON,
                # payload/type mismatch, ...). Drop it and keep serving.
                logger.warning("Discarding invalid message from %s: %s", sender_ip, e)
                continue
            logger.debug("Received %s from %s", parsed.msg_type.value, sender_ip)
            await self.handle_msg(sender_ip, parsed)

    async def run(self):
        logger.info("Kademlia node %s listening on port %d", self.node_id.hex()[:8], self.port)
        self.bind_named_closable(self.recv_loop.__name__, asyncio.create_task(self.recv_loop()))
