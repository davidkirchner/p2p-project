

from base64 import b64encode

from kademlia.types import KademliaKey


def display_key(key: bytes) -> str:
    return b64encode(key).decode('ascii')