


from dataclasses import dataclass
from typing import Any, Callable, Self, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from models import Storage, User, UserID


@dataclass
class PeerEncryption:
    id: UserID
    user: User
    public_key: Ed25519PublicKey

    @classmethod
    async def from_existing(cls, user: User) -> Union["PeerEncryption", "UserEncryption"]:
        if user.private_identity:
            return UserEncryption(
                id=user.id,
                user=user,
                private_key=Ed25519PrivateKey.from_private_bytes(user.private_identity),
                public_key=Ed25519PublicKey.from_public_bytes(user.public_identity)
            )
        else:
            return PeerEncryption(
                id=user.id,
                user=user,
                public_key=Ed25519PublicKey.from_public_bytes(user.public_identity)
            )

    def verify(self, message: bytes, expected: bytes):
        return self.public_key.verify(message, expected)


@dataclass
class UserEncryption(PeerEncryption):
    private_key: Ed25519PrivateKey

    @classmethod
    async def create_new_user(cls, storage: Storage, name: str) -> Self:
        private_key: Ed25519PrivateKey = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_bytes: bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),  # or use BestAvailableEncryption(b"password")
        )

        # Serialize public key (share with peers)
        public_bytes: bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        from .kademlia.kademlia import kademlia_key
        id = kademlia_key(public_bytes)

        user = await storage.User.create(id=id, name=name, public_identity=public_bytes, private_identity=private_bytes)

        return cls(
            id=user.id,
            user=user,
            private_key=private_key,
            public_key=public_key
        )

    def sign(self, message: bytes) -> bytes:
        assert self.private_key
        return self.private_key.sign(message)