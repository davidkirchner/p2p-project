import abc
from contextlib import asynccontextmanager, ContextDecorator, AsyncContextDecorator
from dataclasses import dataclass
from typing import Any, NewType, Self
import uuid
from datetime import datetime



KademliaKey = NewType("KademliaKey", bytes)


UserID = NewType("UserID", KademliaKey)
ChatID = NewType("ChatID", uuid.UUID)
MessageID = NewType("MessageID", uuid.UUID)


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
    
    
class Storage(abc.ABC):
    
    User: type[User]
    Chat: type[Chat]
    Message: type[Message]
    
    @abc.abstractmethod
    def transaction(self) -> AsyncContextDecorator:
        ...
