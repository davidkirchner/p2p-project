"""Headless P2P node: start a node from the environment and run a scripted
scenario, with no terminal UI. Used for shadow tests.

Configuration comes from environment variables
The scenario is given as positional tokens after `--name`:
    wait <seconds>            -- stay alive (e.g. let the network settle)
    recv <seconds>            -- alias of wait, semantically "collect messages"
    send <b64-node-id> <text> -- (init chat if needed and) send a chat message
    fetch-cached              -- pull messages cached in the DHT for our chats

All notable events are written to stdout as a `EVENT` line and shadow reads that
stdout for making assertions in tests.

Example:
    IDENTITY_SEED=<hex> BOOTSTRAP_PEERS="10.0.0.1=<b64pub>" \\
        python src/headless.py --name alice wait 5 send <b64 id> "hi bob" wait 20
"""

import argparse
import asyncio
import base64
import logging
import sys

from config import Config
from db.sqlite_impl import SqliteDatabase
from logging_setup import setup_logging
from models import Chat, ChatID, Message, Storage, UserID
from kademlia.types import KademliaKey
from encryption import UserEncryption
from service import MessagingService, MessageSink

logger = logging.getLogger(__name__)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def emit(event: str, **fields) -> None:
    """Write one structured EVENT line to stdout for shadow tests"""
    parts = " ".join(f"{k}={v}" for k, v in fields.items())
    print(f"EVENT {event} {parts}".rstrip(), flush=True)


class StdoutSink(MessageSink):
    """Prints every inbound chat message as an EVENT line."""

    def __init__(self, database: Storage) -> None:
        super().__init__()
        self.database = database

    async def received_message(self, message: Message):
        try:
            text = message.content.decode("utf-8")
        except UnicodeDecodeError:
            text = repr(message.content)
        emit(
            "recv",
            chat=b64(message.chat),
            sender=b64(message.sender),
            content=text,
        )


async def _find_chat_with_peer(database: Storage, own_id: UserID, peer_id: KademliaKey) -> Chat | None:
    user = await database.User.by_id(own_id)
    for chat_id in await user.chats():
        chat = await database.Chat.by_id(chat_id)
        if peer_id in chat.participants:
            return chat
    return None


async def _cmd_send(service: MessagingService, own_id: UserID, target_b64: str, text: str) -> None:
    peer_id = KademliaKey(base64.b64decode(target_b64))
    chat = await _find_chat_with_peer(service.database, own_id, peer_id)
    if chat is None:
        emit("chat_init", peer=target_b64)
        chat = await service.initialize_chat(own_id, peer_id)
    ok = await service.send_message(
        own_id,
        ChatID(chat.id),
        content=text.encode("utf-8"),
        content_type="text/plain",
    )
    emit("sent", ok=ok, to=target_b64)


async def run_scenario(service: MessagingService, own_id: UserID, tokens: list[str]) -> None:
    i = 0
    while i < len(tokens):
        cmd = tokens[i]
        try:
            if cmd in ("wait", "recv"):
                seconds = float(tokens[i + 1])
                i += 2
                await asyncio.sleep(seconds)
            elif cmd == "send":
                target_b64, text = tokens[i + 1], tokens[i + 2]
                i += 3
                try:
                    await _cmd_send(service, own_id, target_b64, text)
                except Exception as exc:
                    logger.exception("send failed")
                    emit("sent", ok=False, to=target_b64, error=type(exc).__name__)
            elif cmd == "fetch-cached":
                i += 1
                await service.retrieve_cached_messages()
                emit("fetch_cached_done")
            else:
                raise SystemExit(f"Unknown scenario command: {cmd!r}")
        except IndexError:
            raise SystemExit(f"Missing argument(s) for command {cmd!r}")


async def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Headless P2P node")
    parser.add_argument("--name", default="node", help="local user display name")
    args, scenario = parser.parse_known_args(argv)

    setup_logging()
    config = Config.from_env()
    database = await SqliteDatabase.create(config.sqlite_path)

    ue = (
        UserEncryption.from_seed(config.identity_seed)
        if config.identity_seed is not None
        else UserEncryption.create()
    )
    try:
        await database.User.by_id(ue.id)
    except KeyError:
        await ue.store_as_user(storage=database, name=args.name)

    async with MessagingService(database, config, sink=StdoutSink(database)) as service:
        await service.start_node(ue)
        emit("node_started", id=b64(ue.id), name=args.name)
        await run_scenario(service, UserID(KademliaKey(ue.id)), scenario)
        emit("scenario_done", id=b64(ue.id))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
