from models import *
import sqlite3


@dataclass
class SqliteDatabase(Context):
    
    User: type[User]
    Chat: type[Chat]
    Message: type[Message]
    
    conn: sqlite3.Connection
    
    @classmethod
    async def create(cls, path) -> Self:
        
        connection = sqlite3.connect(str(path))
        
        connection.executescript("""
        create table if not exists user (
            id text not null primary key,
            name text not null,
            public_identity blob,
            private_identity blob
        );
        create table if not exists chat (
            id text not null primary key,
            title text,
            description text
        );
        create table if not exists message (
            id text not null primary key,
            chat text not null,
            sender text not null,
            timestamp text not null,
            content blob not null,
            content_type text not null
        );
        
                                 """)
        
        class User_(User):
            pass
        
        
        class Chat_(Chat):
            pass
        
        
        class Message_(Message):
            pass
        
        
        return cls(
            User=User_,
            Chat=Chat_,
            Message=Message_,
            conn=connection
        )
        
    @asynccontextmanager
    async def transaction(self):
        raise NotImplementedError
        yield