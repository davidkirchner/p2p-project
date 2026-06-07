import os
import hashlib

import pytest
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from kademlia import (
    KademliaMsg,
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
)

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
def test_payload_roundtrip(msg_type: MsgType, payload: type[Payload]):
    msg = make_msg(msg_type, payload)
    parsed = KademliaMsg.from_bytes(msg.to_bytes())
    assert parsed == msg
    assert type(parsed.payload) is type(payload)


def test_binary_signature_roundtrip():
    # echte binäre Signatur (kein gültiges UTF-8) muss verlustfrei durchlaufen.
    sig = os.urandom(64)
    msg = make_msg(MsgType.PING, PingPayload(), signature=sig)
    parsed = KademliaMsg.from_bytes(msg.to_bytes())
    assert parsed.signature == sig
