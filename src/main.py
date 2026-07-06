import asyncio
import json
import secrets
from uuid import uuid4
import dotenv

from datetime import datetime, timezone
from typing import cast

from encryption import UserEncryption
from kademlia.kademlia import ChatMsgPayload, KademliaNode, PeerInfo, kademlia_key, Handler as KademliaHandler
from kademlia.types import ContentType, KademliaKey
from logging_setup import setup_logging
from config import Config
from db.sqlite_impl import SqliteDatabase
from models import Chat, ChatID, MessageID, User, UserID
from socket_handler import SocketHandler
from ui.simple import SimpleTerminalUI, Handler as UIHandler

async def main():
    # TODO: ideally, the correct env file is passed in during program invocation.
    # Right now dev.env is hard coded. Please provide one for customization if needed
    dotenv.load_dotenv("dev.env")

    # Configure logging once, right after env files are loaded (LOG_LEVEL is read
    # from the environment). Every module just does logging.getLogger(__name__).

    setup_logging()

    config = Config.from_env()

    socket = SocketHandler()

    kademlia: KademliaNode | None = None

    database = await SqliteDatabase.create(config.sqlite_path)

    async def create_kademlia(ue: UserEncryption):
        nonlocal kademlia
        if kademlia is not None:
            await kademlia.close()

        kademlia = KademliaNode(
            socket=socket,
            node_id=kademlia_key(ue.user.public_identity),
            pubkey=ue.user.public_identity,
            encryption=ue,
            handler=KademliaHandler(
                chat_msg_received
            )
        )
        await kademlia.run()

    async def send_message(user_id: UserID, chat_id: ChatID, content: bytes, content_type: ContentType):
        if not kademlia:
            return # TODO: This should not fail silently

        chat = await database.Chat.by_id(chat_id)
        others = [p for p in chat.participants if p != user_id]
        assert len(others) == 1
        target_peer_id = (await database.User.by_id(others[0])).id

        if not await kademlia.chat_msg_req(peer_id=target_peer_id, chat_id=chat_id, shared_secret=chat.secret, message=content, content_type=content_type):
            raise RuntimeError(f"Message could not be sent in time")


    async def chat_msg_received(sender: PeerInfo, payload: ChatMsgPayload):
        sender_name = sender.ip
        sender_user = await database.User.register_peer(UserID(KademliaKey(sender.id)), sender.pubkey, sender_name)

        chat_id = ChatID(payload.chat_id)

        try:
            target_chat = await database.Chat.by_id(chat_id)
            if sender.id not in target_chat.participants:
                # Something is fishy here
                # chat_id collision by accident or sender tries to spoof a chat
                # TODO: report error back to kademlia
                pass
            if payload.shared_secret != target_chat.secret:
                # same here for the secret
                # TODO: report error back to kademlia
                pass
        except KeyError:
            assert kademlia # This handler is only called if kademlia node is running
            current_user = UserID(KademliaKey(kademlia.node_id))
            target_chat = await database.Chat.create(
                chat_id=chat_id,
                secret=payload.shared_secret,
                title=sender_name,
                description=f"Chat between you and {sender_name}",
                participants=[current_user, sender_user.id]
            )

        last_messages = await target_chat.messages(1)
        if not last_messages:
            prev_id = target_chat.secret
        else:
            prev_id = last_messages[0]

        # TODO: This is broken because B64Bytes are only serialized when model_dump_json is used
        msg_id = MessageID(kademlia_key(prev_id + json.dumps(
            payload.model_dump(),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True
        ).encode("utf-8")))

        ts = datetime.now(tz=timezone.utc)  # TODO: we need the timestamp from the other user! When it was sent, not received
        message = await database.Message.create(id=msg_id, chat=target_chat.id, sender=sender_user.id, timestamp=ts, content=payload.message, content_type=payload.content_type)
        await ui.received_message(message)
        # TODO: This handler must return success/ failure back to kademlia in order
        # to set ChatMsgResponse.success properly


    async def create_user(name: str) -> User:
        ue = await UserEncryption.create_new_user(storage=database, name=name)
        await create_kademlia(ue)
        return ue.user


    async def selection_update(user: UserID | None, chat: ChatID | None):
        nonlocal kademlia
        if user is not None:
            if kademlia is not None and kademlia.node_id == user:
                return # nothing to do here

            ue = cast(UserEncryption, await UserEncryption.from_existing(await database.User.by_id(user)))
            await create_kademlia(ue)
        else:
            if kademlia is not None:
                await kademlia.close()
                kademlia = None

    async def execute_command(user: UserID | None, chat: ChatID | None, args: list[str]):
        pass

    async def initialize_chat(self: UserID, peer_id: KademliaKey) -> Chat:
        assert kademlia
        timeout = 10.0
        try:
            peer = await kademlia.get_peer_infos(peer_id, timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"Peer didn't react in {timeout} seconds")

        peer_name = str(peer.ip) # TODO: implement name alias for nodes and use this instead
        peer_user = await database.User.register_peer(
            id=UserID(KademliaKey(peer.id)),
            public_identity=peer.pubkey,
            name=peer_name
        )

        shared_secret = secrets.token_bytes(32) # 256 Bit, cryptographically safe
        chat = await database.Chat.create(
            chat_id=ChatID(uuid4().bytes),
            secret=shared_secret,
            title=peer_name,
            description=f"Chat between you and {peer_name}",
            participants=[self, peer_user.id],
        )
        # Send an initial chat message so, the chat partner learns about the shared secret
        chat_init_success = await kademlia.chat_msg_req(
            peer_id=peer_id,
            chat_id=chat.id,
            shared_secret=chat.secret,
            message=f"Chat Init from {kademlia.node_id}".encode("utf-8"),
            content_type="text/plain",
        )
        if not chat_init_success:
            await chat.delete()
            raise RuntimeError(f"Chat init message could not be delivered to peer in time")
        return chat

    # this context manager automatically does necessary resource management
    ui_handler = UIHandler(
        send_message,
        create_user,
        selection_update,
        execute_command,
        initialize_chat
    )
    ui: SimpleTerminalUI = await SimpleTerminalUI.create(database=database, handler=ui_handler)
    await ui.run_to_completion()

if __name__ == "__main__":
    asyncio.run(main())
