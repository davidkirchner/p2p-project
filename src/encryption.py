from dataclasses import dataclass, field
from typing import NewType, Self, Union

from nacl.signing import SigningKey, VerifyKey
from nacl.public import SealedBox

from kademlia.types import KademliaKey
from models import Storage, User, UserID


Signature = NewType("Signature", bytes)
EncryptedMsg = NewType("EncryptedMsg", bytes)


@dataclass
class PeerEncryption:
    id: KademliaKey
    verify_key: VerifyKey
    _public_sb: SealedBox = field(init=False)

    def __post_init__(self):
        self._public_sb = SealedBox(self.verify_key.to_curve25519_public_key())

    @property
    def public_bytes(self) -> bytes:
        return bytes(self.verify_key)

    @classmethod
    def from_peer(cls, id: KademliaKey, public_bytes: bytes) -> "PeerEncryption":
        return cls(
            id=id,
            verify_key=VerifyKey(public_bytes)
        )

    @classmethod
    def from_stored(cls, user: User) -> Union["PeerEncryption", "UserEncryption"]:
        if user.private_identity:
            signing_key = SigningKey(user.private_identity)
            return UserEncryption(
                id=user.id,
                verify_key=VerifyKey(user.public_identity),
                signing_key=signing_key
            )
        else:
            return PeerEncryption(
                id=user.id,
                verify_key=VerifyKey(user.public_identity)
            )

    def verify(self, message: bytes, signature: Signature):
        return self.verify_key.verify(message, signature)

    def encrypt(self, receiver: "PeerEncryption", msg: bytes) -> EncryptedMsg:
        return EncryptedMsg(receiver._public_sb.encrypt(msg))


@dataclass
class UserEncryption(PeerEncryption):
    signing_key: SigningKey
    _private_sb: SealedBox = field(init=False)

    def __post_init__(self):
        super().__post_init__()
        self._private_sb = SealedBox(self.signing_key.to_curve25519_private_key())

    @property
    def private_bytes(self) -> bytes:
        """Returns the 32-byte seed — sufficient to reconstruct both keys."""
        return bytes(self.signing_key)

    @classmethod
    def create(cls) -> Self:
        return cls.from_signing_key(SigningKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> Self:
        return cls.from_signing_key(SigningKey(seed=seed))

    @classmethod
    def from_signing_key(cls, signing_key: SigningKey) -> Self:
        verify_key = signing_key.verify_key
        public_bytes = bytes(verify_key)

        from kademlia.kademlia import kademlia_key
        id = UserID(kademlia_key(public_bytes))

        return cls(
            id=id,
            verify_key=verify_key,
            signing_key=signing_key
        )

    async def store_as_user(self, storage: Storage, name: str) -> User:
        return await storage.User.create(self.id, name, self.public_bytes, self.private_bytes)

    def sign(self, message: bytes) -> Signature:
        return Signature(self.signing_key.sign(message).signature)

    def decrypt(self, message: EncryptedMsg) -> bytes:
        """Decrypt an encrypted message. Raises CryptoError if decryption fails."""
        return self._private_sb.decrypt(message)