import asyncio
from hashlib import sha256
import json
import logging
import secrets
from uuid import uuid4
import dotenv

from datetime import datetime, timezone
from typing import cast

from encryption import EncryptedMsg, PeerEncryption, UserEncryption
import encryption
from kademlia.kademlia import ChatMsgPayload, KademliaNode, MsgType, Peer, kademlia_key, Handler as KademliaHandler
from kademlia.types import ContentType, KademliaKey
from logging_setup import setup_logging
from config import Config
from db.sqlite_impl import SqliteDatabase
from models import Chat, ChatID, MessageID, User, UserID
from socket_handler import SocketHandler
from ui.simple import SimpleTerminalUI, Handler as UIHandler

def msg_hash(prev_hash: bytes, current_msg: ChatMsgPayload) -> bytes:
    current_msg_bytes = current_msg.model_dump_json(ensure_ascii=False).encode("utf-8")
    return sha256(prev_hash + current_msg_bytes).digest()


async def main():
    # TODO: ideally, the correct env file is passed in during program invocation.
    # Right now dev.env is hard coded. Please provide one for customization if needed
    dotenv.load_dotenv("dev.env")

    # Configure logging once, right after env files are loaded (LOG_LEVEL is read
    # from the environment). Every module just does logging.getLogger(__name__).

    setup_logging()
    logger = logging.getLogger(__name__)

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
            node_id=ue.id,
            pubkey=ue.public_bytes,
            encryption=ue,
            handler=KademliaHandler(
                chat_msg_received,
                cached_chat_msg_received
            )
        )
        await kademlia.run()

    async def send_message(user_id: UserID, chat_id: ChatID, content: bytes, content_type: ContentType):
        if not kademlia:
            return # TODO: This should not fail silently

        # lets first get info about the other guy from the database.
        chat = await database.Chat.by_id(chat_id)
        others = [p for p in chat.participants if p != user_id]
        assert len(others) == 1
        target_peer = await database.User.by_id(others[0])

        # now calculate the message contents (create a ChatMsgPayload instance)...
        msg_payload = ChatMsgPayload(chat_id=chat_id, shared_secret=chat.secret, message=content, content_type=content_type, timestamp=datetime.now(tz=timezone.utc))
        last_messages = await chat.messages(1)
        prev_id = chat.secret if not last_messages else last_messages[0]
        # and calculate the message ID.
        # TODO: this is mostly duplicated logic from below. This stuff needs some major refactor at some point!
        msg_id = MessageID(msg_hash(prev_id, msg_payload))

        if await kademlia.chat_msg_req(peer_id=target_peer.id, chat_id=chat_id, shared_secret=chat.secret, message=content, content_type=content_type, timestamp=msg_payload.timestamp):
            # message sent successfully, store in db and finish
            await database.Message.create(
                id=msg_id,
                chat=chat.id,
                sender=user_id,
                timestamp=msg_payload.timestamp,
                content=content,
                content_type=content_type
            )
            return

        # could not send the message directly (in time)
        # in this case, we cache offline
        # we first calculate the location like this
        location_key = kademlia_key(prev_id + user_id)
        target_peer_encr = PeerEncryption.from_stored(target_peer)

        # wrap the payload in the same signed KademliaMsg envelope used on the wire,
        # so the receiver can decode it with from_bytes() and verify the signature
        cached_msg = kademlia.new_msg(MsgType.CHAT_MSG, msg_payload)
        offline_store_bytes_raw = cached_msg.to_bytes()
        if kademlia.encrypt:
            # encrypt it for only the receiver (the other chat participant, not the cache location) to read
            offline_store_bytes_encr = kademlia.encryption.encrypt(msg=offline_store_bytes_raw, receiver=target_peer_encr)
        else:
            offline_store_bytes_encr = EncryptedMsg(offline_store_bytes_raw)

        # then find all the neighbouring nodes to that location and ask them to store (please)
        for offline_cache_peer in await kademlia.find_node(location_key):
            if not await kademlia.store_req(offline_cache_peer, value=offline_store_bytes_encr):
                logger.warning(f"Could not store message at location {offline_cache_peer.id} for some reason")
            else:
                logger.info(f"Cached message at location {offline_cache_peer.id}")

        # and now we're done. Waiting for them to pick up the message

    async def chat_msg_received(sender: Peer, payload: ChatMsgPayload):
        sender_name = sender.ip
        sender_user = await database.User.register_peer(UserID(KademliaKey(sender.id)), sender.pubkey, sender_name)

        chat_id = ChatID(payload.chat_id)

        try:
            target_chat = await database.Chat.by_id(chat_id)
            if sender.id not in target_chat.participants:
                # chat_id collision by accident or sender tries to spoof a chat
                raise ValueError(f"SenderID is not a participant of chat {chat_id}")
            if payload.shared_secret != target_chat.secret:
                # same here for the secret
                raise ValueError(f"Chat secret does not match secret from existing chat {chat_id}")
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

        # we need to fetch this so we can calculate the message id
        last_messages = await target_chat.messages(1)
        prev_id = target_chat.secret if not last_messages else last_messages[0]
        msg_id = MessageID(msg_hash(prev_id, payload))

        # TODO: Deuplication! The same message may arrive twice => Message.create will fail
        message = await database.Message.create(
            id=msg_id,
            chat=target_chat.id,
            sender=sender_user.id,
            timestamp=payload.timestamp ,
            content=payload.message,
            content_type=payload.content_type
        )
        await ui.received_message(message)

    async def cached_chat_msg_received(
        sender_id: KademliaKey,
        sender_pubkey: bytes,
        payload: ChatMsgPayload
    ):
        assert kademlia

        chat = await database.Chat.by_id(ChatID(payload.chat_id))

        current_user = UserID(KademliaKey(kademlia.node_id))

        # Find the other chat participant
        sender_user_id = next(
            participant
            for participant in chat.participants
            if participant != current_user
        )

        sender_user = await database.User.by_id(sender_user_id)

        peer = Peer(
            id=KademliaKey(sender_user.id),
            ip=sender_user.name,
            pubkey=sender_pubkey,
        )

        await chat_msg_received(
            sender=peer,
            payload=payload,
        )

    async def create_user(name: str) -> User:
        ue = UserEncryption.create()
        user = await ue.store_as_user(storage=database, name=name)
        await create_kademlia(ue)
        return user


    async def selection_update(user: UserID | None, chat: ChatID | None):
        nonlocal kademlia
        if user is not None:
            if kademlia is not None and kademlia.node_id == user:
                return # nothing to do here

            ue = cast(UserEncryption, UserEncryption.from_stored(await database.User.by_id(user)))
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
            timestamp=datetime.now(tz=timezone.utc)
        )
        if not chat_init_success:
            await chat.delete()
            # See chat_msg_received for possible failures
            raise RuntimeError(f"Chat initialization failed")
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
