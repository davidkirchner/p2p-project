import uuid, base64, hashlib
from enum import Enum
from typing import Annotated, Self
from pydantic import BaseModel, Field, BeforeValidator, PlainSerializer, SerializeAsAny, model_validator


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


# Registry: msg_type -> payload class. The only place a new MsgType has to
# register its payload.
PAYLOAD_TYPES: dict[MsgType, type[Payload]] = {
    MsgType.PING: PingPayload,
    MsgType.PONG: PongPayload,
    MsgType.STORE: StorePayload,
    MsgType.STORE_REPLY: StoreReplyPayload,
    MsgType.FIND_NODE: FindNodePayload,
    MsgType.FIND_NODE_REPLY: FindNodeReplyPayload,
    MsgType.FIND_VALUE: FindValuePayload,
    MsgType.FIND_VALUE_REPLY: FindValueReplyPayload,
}


class KademliaMsg(BaseModel):
    msg_type: MsgType
    msg_id: B64Bytes = Field(default_factory=lambda: uuid.uuid4().bytes)
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
