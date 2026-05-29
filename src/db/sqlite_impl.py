from pathlib import Path
import models as m
import sqlite3
import uuid
from datetime import datetime
from dataclasses import dataclass
from typing import Self
from contextlib import asynccontextmanager


@dataclass
class SqliteDatabase(m.Context):

    User: type[m.User]
    Chat: type[m.Chat]
    Message: type[m.Message]

    conn: sqlite3.Connection

    @classmethod
    async def create(cls, path: Path) -> Self:

        connection = sqlite3.connect(str(path))

        connection.executescript("""
        CREATE TABLE IF NOT EXISTS user (
            id TEXT NOT NULL PRIMARY KEY,
            name TEXT NOT NULL,
            public_identity BLOB,
            private_identity BLOB
        );
        CREATE TABLE IF NOT EXISTS chat (
            id TEXT NOT NULL PRIMARY KEY,
            title TEXT,
            description TEXT
        );
        CREATE TABLE IF NOT EXISTS chat_participant (
            chat_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            PRIMARY KEY (chat_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS message (
            id TEXT NOT NULL PRIMARY KEY,
            chat TEXT NOT NULL,
            sender TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            content BLOB NOT NULL,
            content_type TEXT NOT NULL
        );
        """)
        connection.commit()

        # --- User implementation ---
        @dataclass
        class User(m.User):
            id: m.UserID
            name: str
            public_identity: bytes
            private_identity: bytes
            
            @classmethod
            async def by_id(cls, id: m.UserID) -> "User":
                row = connection.execute(
                    "SELECT id, name, public_identity, private_identity FROM user WHERE id = ?",
                    (str(id),)
                ).fetchone()
                if row is None:
                    raise KeyError(f"User with id {id} not found")
                return cls(
                    id=m.UserID(uuid.UUID(row[0])),
                    name=row[1],
                    public_identity=row[2] or b"",
                    private_identity=row[3] or b"",
                )

            async def chats(self) -> list[m.ChatID]:
                rows = connection.execute(
                    "SELECT chat_id FROM chat_participant WHERE user_id = ?",
                    (str(self.id),)
                ).fetchall()
                return [m.ChatID(uuid.UUID(r[0])) for r in rows]

            def __repr__(self) -> str:
                return f"User(id={self.id!r}, name={self.name!r})"

        # --- Chat implementation ---
        @dataclass
        class Chat(m.Chat):
            id: m.ChatID
            title: str
            description: str
            participants: list[m.UserID]

            @classmethod
            async def by_id(cls, id: m.ChatID) -> "Chat":
                row = connection.execute(
                    "SELECT id, title, description FROM chat WHERE id = ?",
                    (str(id),)
                ).fetchone()
                if row is None:
                    raise KeyError(f"Chat with id {id} not found")
                participant_rows = connection.execute(
                    "SELECT user_id FROM chat_participant WHERE chat_id = ?",
                    (str(id),)
                ).fetchall()
                participants = [m.UserID(uuid.UUID(r[0])) for r in participant_rows]
                return cls(
                    id=m.ChatID(uuid.UUID(row[0])),
                    title=row[1] or "",
                    description=row[2] or "",
                    participants=participants,
                )

            async def messages(self, n: int, before: datetime) -> list[m.MessageID]:
                rows = connection.execute(
                    "SELECT id FROM message WHERE chat = ? AND timestamp < ? ORDER BY timestamp DESC LIMIT ?",
                    (str(self.id), before.isoformat(), n)
                ).fetchall()
                return [m.MessageID(uuid.UUID(r[0])) for r in rows]

            def __repr__(self) -> str:
                return f"Chat(id={self.id!r}, title={self.title!r})"

        # --- Message implementation ---
        @dataclass
        class Message(m.Message):
            id: m.MessageID
            chat: m.ChatID
            sender: m.UserID
            timestamp: datetime
            content: bytes
            content_type: str

            @classmethod
            async def by_id(cls, id: m.MessageID) -> "Message":
                row = connection.execute(
                    "SELECT id, chat, sender, timestamp, content, content_type FROM message WHERE id = ?",
                    (str(id),)
                ).fetchone()
                if row is None:
                    raise KeyError(f"Message with id {id} not found")
                return cls(
                    id=m.MessageID(uuid.UUID(row[0])),
                    chat=m.ChatID(uuid.UUID(row[1])),
                    sender=m.UserID(uuid.UUID(row[2])),
                    timestamp=datetime.fromisoformat(row[3]),
                    content=row[4],
                    content_type=row[5],
                )

            def __repr__(self) -> str:
                return f"Message(id={self.id!r}, chat={self.chat!r}, sender={self.sender!r})"

        return cls(
            User=User,
            Chat=Chat,
            Message=Message,
            conn=connection,
        )

    @asynccontextmanager
    async def transaction(self):
        cursor = self.conn.cursor()
        cursor.execute("BEGIN")
        try:
            yield cursor
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    # --- Factory / creation helpers ---

    async def create_user(self, name: str, public_identity: bytes = b"", private_identity: bytes = b"") -> m.User:
        user_id = m.UserID(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO user (id, name, public_identity, private_identity) VALUES (?, ?, ?, ?)",
            (str(user_id), name, public_identity, private_identity),
        )
        self.conn.commit()
        return await self.User.by_id(user_id)

    async def create_chat(self, title: str, description: str = "", participants: list[m.UserID] | None = None) -> m.Chat:
        chat_id = m.ChatID(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO chat (id, title, description) VALUES (?, ?, ?)",
            (str(chat_id), title, description),
        )
        for uid in (participants or []):
            self.conn.execute(
                "INSERT INTO chat_participant (chat_id, user_id) VALUES (?, ?)",
                (str(chat_id), str(uid)),
            )
        self.conn.commit()
        return await self.Chat.by_id(chat_id)

    async def create_message(self, chat: m.ChatID, sender: m.UserID, content: bytes, content_type: str = "text/plain") -> m.Message:
        message_id = m.MessageID(uuid.uuid4())
        timestamp = datetime.now(tz=None)
        self.conn.execute(
            "INSERT INTO message (id, chat, sender, timestamp, content, content_type) VALUES (?, ?, ?, ?, ?, ?)",
            (str(message_id), str(chat), str(sender), timestamp.isoformat(), content, content_type),
        )
        self.conn.commit()
        return await self.Message.by_id(message_id)