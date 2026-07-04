from pathlib import Path
import secrets
import models as m
import sqlite3
import uuid
from datetime import datetime
from dataclasses import dataclass
from typing import Self
from contextlib import asynccontextmanager


@dataclass
class SqliteDatabase(m.Storage):

    User: type[m.User]
    Chat: type[m.Chat]
    Message: type[m.Message]

    conn: sqlite3.Connection

    @classmethod
    async def create(cls, path: Path) -> Self:

        connection = sqlite3.connect(str(path))
        
        # Enable recommended pragmas
        connection.execute("PRAGMA journal_mode = WAL;")
        connection.execute("PRAGMA foreign_keys = ON;")
        connection.execute("PRAGMA busy_timeout = 5000;")
        connection.execute("PRAGMA synchronous = NORMAL;")

        connection.executescript("""
        CREATE TABLE IF NOT EXISTS user (
            id TEXT NOT NULL PRIMARY KEY,
            name TEXT NOT NULL,
            public_identity BLOB,
            private_identity BLOB
        );
        CREATE TABLE IF NOT EXISTS chat (
            id BLOB NOT NULL PRIMARY KEY,
            title TEXT,
            description TEXT
        );
        CREATE TABLE IF NOT EXISTS chat_participant (
            chat_id BLOB NOT NULL,
            user_id TEXT NOT NULL,
            PRIMARY KEY (chat_id, user_id),
            FOREIGN KEY (chat_id) REFERENCES chat(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS message (
            id TEXT NOT NULL PRIMARY KEY,
            chat BLOB NOT NULL,
            sender TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            content BLOB NOT NULL,
            content_type TEXT NOT NULL,
            FOREIGN KEY (chat) REFERENCES chat(id) ON DELETE CASCADE,
            FOREIGN KEY (sender) REFERENCES user(id) ON DELETE SET NULL
        );
        """)
        connection.commit()

        # --- User implementation ---
        @dataclass
        class User(m.User):
            id: m.UserID
            name: str | None
            public_identity: bytes
            private_identity: bytes | None

            @classmethod
            async def create(cls, id: m.KademliaKey, name: str, public_identity: bytes = b"", private_identity: bytes = b"") -> "User":
                user_id = m.UserID(id)
                connection.execute(
                    "INSERT INTO user (id, name, public_identity, private_identity) VALUES (?, ?, ?, ?)",
                    (str(user_id), name, public_identity, private_identity),
                )
                connection.commit()
                return await cls.by_id(user_id)

            @classmethod
            async def by_id(cls, id: m.UserID) -> "User":
                row = connection.execute(
                    "SELECT id, name, public_identity, private_identity FROM user WHERE id = ?",
                    (str(id),)
                ).fetchone()
                if row is None:
                    raise KeyError(f"User with id {id} not found")
                return cls(
                    id=m.UserID(row[0]),
                    name=row[1],
                    public_identity=row[2] or b"",
                    private_identity=row[3] or b"",
                )

            async def save(self) -> None:
                connection.execute(
                    "UPDATE user SET name = ?, public_identity = ?, private_identity = ? WHERE id = ?",
                    (self.name, self.public_identity, self.private_identity, str(self.id)),
                )
                connection.commit()

            async def delete(self) -> None:
                connection.execute(
                    "DELETE FROM chat_participant WHERE user_id = ?",
                    (str(self.id),)
                )
                connection.execute(
                    "DELETE FROM user WHERE id = ?",
                    (str(self.id),)
                )
                connection.commit()

            async def chats(self) -> list[m.ChatID]:
                rows = connection.execute(
                    "SELECT chat_id FROM chat_participant WHERE user_id = ?",
                    (str(self.id),)
                ).fetchall()
                return [m.ChatID(r[0]) for r in rows]
            
            @classmethod
            async def local_profiles(cls) -> list[m.UserID]:
                rows = connection.execute("select id from user where private_identity notnull").fetchall()
                return [m.UserID(r[0]) for r in rows]

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
            async def create(cls, title: str, description: str = "", participants: list[m.UserID] | None = None) -> "Chat":
                chat_id = m.ChatID(secrets.token_bytes(32))
                connection.execute(
                    "INSERT INTO chat (id, title, description) VALUES (?, ?, ?)",
                    (str(chat_id), title, description),
                )
                for uid in (participants or []):
                    connection.execute(
                        "INSERT INTO chat_participant (chat_id, user_id) VALUES (?, ?)",
                        (str(chat_id), str(uid)),
                    )
                connection.commit()
                return await cls.by_id(chat_id)

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
                participants = [m.UserID(r[0]) for r in participant_rows]
                return cls(
                    id=m.ChatID(row[0]),
                    title=row[1] or "",
                    description=row[2] or "",
                    participants=participants,
                )

            async def save(self) -> None:
                connection.execute(
                    "UPDATE chat SET title = ?, description = ? WHERE id = ?",
                    (self.title, self.description, str(self.id)),
                )
                # Sync participants: delete all and re-insert
                connection.execute(
                    "DELETE FROM chat_participant WHERE chat_id = ?",
                    (str(self.id),)
                )
                for uid in self.participants:
                    connection.execute(
                        "INSERT INTO chat_participant (chat_id, user_id) VALUES (?, ?)",
                        (str(self.id), str(uid)),
                    )
                connection.commit()

            async def delete(self) -> None:
                connection.execute(
                    "DELETE FROM chat_participant WHERE chat_id = ?",
                    (str(self.id),)
                )
                connection.execute(
                    "DELETE FROM message WHERE chat = ?",
                    (str(self.id),)
                )
                connection.execute(
                    "DELETE FROM chat WHERE id = ?",
                    (str(self.id),)
                )
                connection.commit()

            async def messages(self, n: int, before: datetime) -> list[m.MessageID]:
                rows = connection.execute(
                    "SELECT id FROM message WHERE chat = ? AND timestamp < ? ORDER BY timestamp DESC LIMIT ?",
                    (str(self.id), before.isoformat(), n)
                ).fetchall()
                return [m.MessageID(r[0]) for r in rows]

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
            async def create(cls, chat: m.ChatID, sender: m.UserID, content: bytes, content_type: str = "text/plain") -> "Message":
                message_id = m.MessageID(secrets.token_bytes(32))
                timestamp = datetime.now(tz=None)
                connection.execute(
                    "INSERT INTO message (id, chat, sender, timestamp, content, content_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (str(message_id), str(chat), str(sender), timestamp.isoformat(), content, content_type),
                )
                connection.commit()
                return await cls.by_id(message_id)

            @classmethod
            async def by_id(cls, id: m.MessageID) -> "Message":
                row = connection.execute(
                    "SELECT id, chat, sender, timestamp, content, content_type FROM message WHERE id = ?",
                    (str(id),)
                ).fetchone()
                if row is None:
                    raise KeyError(f"Message with id {id} not found")
                return cls(
                    id=m.MessageID(row[0]),
                    chat=m.ChatID(row[1]),
                    sender=m.UserID(row[2]),
                    timestamp=datetime.fromisoformat(row[3]),
                    content=row[4],
                    content_type=row[5],
                )

            async def save(self) -> None:
                connection.execute(
                    "UPDATE message SET chat = ?, sender = ?, timestamp = ?, content = ?, content_type = ? WHERE id = ?",
                    (str(self.chat), str(self.sender), self.timestamp.isoformat(), self.content, self.content_type, str(self.id)),
                )
                connection.commit()

            async def delete(self) -> None:
                connection.execute(
                    "DELETE FROM message WHERE id = ?",
                    (str(self.id),)
                )
                connection.commit()

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