import abc
import uuid
from contextlib import AsyncContextDecorator
from typing import NewType, Self
from datetime import datetime
from kademlia.types import KademliaKey

UserID = NewType("UserID", KademliaKey)
ChatID = NewType("ChatID", bytes)
MessageID = NewType("MessageID", bytes)


class Thing(abc.ABC):
    @classmethod
    @abc.abstractmethod
    async def by_id(cls, id) -> Self:
        ...

    @abc.abstractmethod
    async def delete(self):
        ...

    @abc.abstractmethod
    async def save(self):
        ...

    @classmethod
    @abc.abstractmethod
    async def create(cls, *args, **kwargs) -> Self:
        ...


class User(Thing):
    id: UserID
    name: str | None
    public_identity: bytes
    private_identity: bytes | None
    
    @classmethod
    @abc.abstractmethod
    async def create(cls, id: KademliaKey, name: str, public_identity: bytes = b"", private_identity: bytes = b"") -> Self:
        ...
    
    @classmethod
    @abc.abstractmethod
    async def local_profiles(cls) -> list[UserID]:
        ...

    @abc.abstractmethod
    async def chats(self) -> list[ChatID]:
        ...


class Chat(Thing):
    id: ChatID
    title: str
    description: str

    participants: list[UserID]

    @classmethod
    @abc.abstractmethod
    async def create(cls, title: str, description: str = "", participants: list[UserID] | None = None) -> "Chat":
        ...
        
    @abc.abstractmethod
    async def messages(self, n: int, before: datetime) -> list[MessageID]:
        pass
    

class Message(Thing):
    id: MessageID
    chat: ChatID
    sender: UserID
    timestamp: datetime

    content: bytes
    content_type: str
    
    @classmethod
    @abc.abstractmethod
    async def create(cls, chat: ChatID, sender: UserID, content: bytes, content_type: str = "text/plain") -> "Message":
        pass


class Storage(abc.ABC):

    User: type[User]
    Chat: type[Chat]
    Message: type[Message]

    @abc.abstractmethod
    def transaction(self) -> AsyncContextDecorator:
        ...
