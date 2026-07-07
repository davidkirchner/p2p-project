


from dataclasses import dataclass, field
from typing import NewType, Self, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from nacl.public import PrivateKey, SealedBox, PublicKey

from kademlia.types import KademliaKey
from models import Storage, User, UserID


Signature = NewType("Signature", bytes)
EncryptedMsg = NewType("EncryptedMsg", bytes)


@dataclass
class PeerEncryption:
    id: KademliaKey
    public_key: Ed25519PublicKey
    _public_sb: SealedBox = field(init=False)
    
    def __post_init__(self):
        self._public_sb = SealedBox(PublicKey(self.public_bytes))
    
    @property
    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes_raw()
    
    @classmethod
    def from_peer(cls, id: KademliaKey, public_bytes: bytes) -> "PeerEncryption":
        return cls(
            id=id,
            public_key=Ed25519PublicKey.from_public_bytes(public_bytes)
        )
    
    @classmethod
    async def from_stored(cls, user: User) -> Union["PeerEncryption", "UserEncryption"]:
        if user.private_identity:
            return UserEncryption(
                id=user.id,
                private_key=Ed25519PrivateKey.from_private_bytes(user.private_identity),
                public_key=Ed25519PublicKey.from_public_bytes(user.public_identity)
            )
        else:
            return PeerEncryption(
                id=user.id,
                public_key=Ed25519PublicKey.from_public_bytes(user.public_identity)
            )

    def verify(self, message: bytes, signature: Signature):
        return self.public_key.verify(signature=signature, data=message)
    
    def encrypt(self, receiver: "PeerEncryption", msg: bytes) -> EncryptedMsg:
        # self is the receiver
        return EncryptedMsg(receiver._public_sb.encrypt(msg))
    

@dataclass
class UserEncryption(PeerEncryption):
    private_key: Ed25519PrivateKey
    _private_sb: SealedBox = field(init=False)
    
    def __post_init__(self):
        super().__post_init__()
        self._private_sb = SealedBox(PrivateKey(self.private_bytes))
    
    @property
    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes_raw()
        
    @classmethod
    def create(cls) -> Self:
        private_key: Ed25519PrivateKey = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize public key (share with peers)
        public_bytes: bytes = public_key.public_bytes_raw()
        
        from kademlia.kademlia import kademlia_key
        id = UserID(kademlia_key(public_bytes))
        
        return cls(
            id=id,
            private_key=private_key,
            public_key=public_key
        )
        
    async def store_as_user(self, storage: Storage, name: str) -> User:
        return await storage.User.create(self.id, name, self.public_bytes, self.private_bytes)

    def sign(self, message: bytes) -> Signature:
        return Signature(self.private_key.sign(message))
    
    def decrypt(self, message: EncryptedMsg) -> bytes:
        """Decrypt an encrypted message. Raises one of the many CryptoErrors of PyNaCl if something goes wrong."""
        return self._private_sb.decrypt(message)