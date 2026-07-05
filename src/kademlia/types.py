import base64
from typing import Annotated, Literal, NewType
from pydantic import BeforeValidator, PlainSerializer

def _b64_decode(v: str | bytes) -> bytes:
    # str -> from JSON: decode base64 to bytes
    # bytes -> already raw bytes, pass through
    return base64.b64decode(v) if isinstance(v, str) else v


# Raw bytes in code, base64 on the wire (JSON has no native bytes type)
type B64Bytes = Annotated[
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

KademliaKey = NewType("KademliaKey", B64Bytes)

type ContentType = Literal["text/plain"]