import abc
from contextlib import asynccontextmanager, ContextDecorator, AsyncContextDecorator
from dataclasses import dataclass
from typing import Any, NewType, Self
import uuid
from datetime import datetime


UserID = NewType("UserID", uuid.UUID)
ChatID = NewType("ChatID", uuid.UUID)
MessageID = NewType("MessageID", uuid.UUID)


class Test(abc.ABC):
    @abc.abstractmethod
    @classmethod
    async def by_id(cls, id) -> Self:
        ...


class User(Test):
    id: UserID
    name: str
    public_identity: bytes
    private_identity: bytes
    
    @abc.abstractmethod
    async def chats(self) -> list[ChatID]:
        pass
    
    
class Chat(Test):
    id: ChatID
    title: str
    description: str
    
    participants: list[UserID]
    
    @abc.abstractmethod
    async def messages(self, n: int, before: datetime) -> list[MessageID]:
        pass
    
class Message(Test):
    id: MessageID
    chat: ChatID
    sender: UserID
    timestamp: datetime
    
    content: bytes
    content_type: str
    
    
class Context(abc.ABC):
    @abc.abstractmethod
    def transaction(self) -> AsyncContextDecorator:
        ...