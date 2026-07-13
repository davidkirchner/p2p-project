import logging
import secrets
from datetime import datetime, timezone
from hashlib import sha256
from typing import Callable, Literal, cast
from uuid import uuid4

from closable import Closable
from config import Config
from encryption import EncryptedMsg, PeerEncryption, UserEncryption
from handlers import HandlerBase
from kademlia.kademlia import (
    ChatMsgPayload,
    KademliaNode,
    MsgType,
    Peer,
    kademlia_key,
    Handler as KademliaHandler,
)
from kademlia.types import ContentType, KademliaKey
from models import Chat, ChatID, Message, MessageID, Storage, User, UserID
from socket_handler import AnySocketHandler, SocketHandler

logger = logging.getLogger(__name__)


def msg_hash(prev_hash: bytes, current_msg: ChatMsgPayload) -> bytes:
    current_msg_bytes = current_msg.model_dump_json(ensure_ascii=False).encode("utf-8")
    return sha256(prev_hash + current_msg_bytes).digest()


class MessageSink(HandlerBase):
    async def received_message(self, message: Message):
        pass


class MessagingService(Closable):
    def __init__(
        self,
        database: Storage,
        config: Config,
        sink: MessageSink | None = None,
        socket_factory: Callable[[], AnySocketHandler] = SocketHandler,
    ) -> None:
        super().__init__()
        self.database = database
        self.config = config
        self.sink = sink if sink is not None else MessageSink()
        self._socket_factory = socket_factory
        self.kademlia: KademliaNode | None = None

    async def start_node(self, ue: UserEncryption) -> KademliaNode:
        """(Re)start the Kademlia node with the given identity."""
        if self.kademlia is not None:
            await self.kademlia.close()

        bootstrap_peers = (
            list(self.config.bootstrap_peers)
            if self.config.bootstrap_peers is not None
            else None
        )
        self.kademlia = KademliaNode(
            socket=self._socket_factory(),
            node_id=ue.id,
            pubkey=ue.public_bytes,
            encryption=ue,
            handler=KademliaHandler(
                chat_msg_received=self._chat_msg_received,
                cached_chat_msg_received=self._cached_chat_msg_received,
            ),
            host=self.config.bind_host,
            port=self.config.port,
            bootstrap_peers=bootstrap_peers,
        )
        await self.kademlia.run()
        await self.retrieve_cached_messages()
        return self.kademlia

    async def create_user(self, name: str) -> User:
        ue = UserEncryption.create()
        user = await ue.store_as_user(storage=self.database, name=name)
        await self.start_node(ue)
        return user

    async def selection_update(self, user: UserID | None, chat: ChatID | None):
        if user is not None:
            if self.kademlia is not None and self.kademlia.node_id == user:
                return  # nothing to do here
            ue = cast(UserEncryption, UserEncryption.from_stored(await self.database.User.by_id(user)))
            await self.start_node(ue)
        else:
            if self.kademlia is not None:
                await self.kademlia.close()
                self.kademlia = None

    async def execute_command(self, user: UserID | None, chat: ChatID | None, args: list[str]):
        pass

    async def send_message(
        self,
        user_id: UserID,
        chat_id: ChatID,
        content: bytes,
        content_type: ContentType,
    ) -> Literal["delivered", "cached", "failed"]:
        if not self.kademlia:
            raise RuntimeError("Cannot send a message: no node is running")

        # lets first get info about the other guy from the database.
        chat = await self.database.Chat.by_id(chat_id)
        others = [p for p in chat.participants if p != user_id]
        assert len(others) == 1
        target_peer = await self.database.User.by_id(others[0])

        # now calculate the message contents (create a ChatMsgPayload instance)...
        msg_payload = ChatMsgPayload(
            chat_id=chat_id,
            shared_secret=chat.secret,
            message=content,
            content_type=content_type,
            timestamp=datetime.now(tz=timezone.utc),
        )
        last_messages = await chat.messages(1)
        prev_id = chat.secret if not last_messages else last_messages[0]
        # and calculate the message ID.
        msg_id = MessageID(msg_hash(prev_id, msg_payload))

        if await self.kademlia.chat_msg_req(
            peer_id=target_peer.id,
            chat_id=chat_id,
            shared_secret=chat.secret,
            message=content,
            content_type=content_type,
            timestamp=msg_payload.timestamp,
        ):
            # message sent successfully, store in db and finish
            await self.database.Message.create(
                id=msg_id,
                chat=chat.id,
                sender=user_id,
                timestamp=msg_payload.timestamp,
                content=content,
                content_type=content_type,
            )
            return "delivered"

        # could not send the message directly (in time) -> cache offline.
        # The location is derived from the current chain head and our own id.
        location_key = kademlia_key(prev_id + user_id)
        target_peer_encr = PeerEncryption.from_stored(target_peer)

        # wrap the payload in the same signed KademliaMsg envelope used on the wire,
        # so the receiver can decode it with from_bytes() and verify the signature
        cached_msg = self.kademlia.new_msg(MsgType.CHAT_MSG, msg_payload)
        offline_store_bytes_raw = cached_msg.to_bytes()
        if self.kademlia.encrypt:
            # encrypt it for only the receiver (the other chat participant, not the
            # cache location) to read
            offline_store_bytes_encr = self.kademlia.encryption.encrypt(
                msg=offline_store_bytes_raw, receiver=target_peer_encr
            )
        else:
            offline_store_bytes_encr = EncryptedMsg(offline_store_bytes_raw)

        caching_succeeded = False
        # then find all the neighbouring nodes to that location and ask them to store
        for offline_cache_peer in await self.kademlia.find_node(location_key):
            if not await self.kademlia.store_req(offline_cache_peer, key=location_key, value=offline_store_bytes_encr):
                logger.warning(f"Could not store message at location {offline_cache_peer.id} for some reason")
            else:
                caching_succeeded = True
                logger.info(f"Cached message at location {offline_cache_peer.id}")

        if caching_succeeded:
            await self.database.Message.create(
                id=msg_id,
                chat=chat.id,
                sender=user_id,
                timestamp=msg_payload.timestamp,
                content=content,
                content_type=content_type,
            )
            return "cached"
        return "failed"

    async def initialize_chat(self, own_id: UserID, peer_id: KademliaKey) -> Chat:
        assert self.kademlia
        timeout = 10.0
        try:
            peer = await self.kademlia.get_peer_infos(peer_id, timeout=timeout)
        except TimeoutError:
            raise TimeoutError(f"Peer didn't react in {timeout} seconds")

        peer_name = str(peer.ip)  # TODO: implement name alias for nodes and use this instead
        peer_user = await self.database.User.register_peer(
            id=UserID(KademliaKey(peer.id)),
            public_identity=peer.pubkey,
            name=peer_name,
        )

        shared_secret = secrets.token_bytes(32)  # 256 Bit, cryptographically safe
        chat = await self.database.Chat.create(
            chat_id=ChatID(uuid4().bytes),
            secret=shared_secret,
            title=peer_name,
            description=f"Chat between you and {peer_name}",
            participants=[own_id, peer_user.id],
        )
        # Send an initial chat message so the chat partner learns about the shared secret
        init_content = f"Chat Init from {self.kademlia.node_id.hex()}".encode("utf-8")
        init_ts = datetime.now(tz=timezone.utc)
        chat_init_success = await self.kademlia.chat_msg_req(
            peer_id=peer_id,
            chat_id=chat.id,
            shared_secret=chat.secret,
            message=init_content,
            content_type="text/plain",
            timestamp=init_ts,
        )
        if not chat_init_success:
            await chat.delete()
            raise RuntimeError("Chat initialization failed")

        # receipient stores the init message, so we have to store it also. Otherwise the hash chains diverge
        init_payload = ChatMsgPayload(
            chat_id=chat.id,
            shared_secret=chat.secret,
            message=init_content,
            content_type="text/plain",
            timestamp=init_ts,
        )
        init_id = MessageID(msg_hash(chat.secret, init_payload))
        await self.database.Message.create(
            id=init_id,
            chat=chat.id,
            sender=own_id,
            timestamp=init_ts,
            content=init_content,
            content_type="text/plain",
        )
        return chat

    async def retrieve_cached_messages(self) -> None:
        """Pull any messages cached in the DHT for all chats"""
        logger.info("Searching for cached messages in the network")
        assert self.kademlia
        current_user = UserID(KademliaKey(self.kademlia.node_id))
        chat_ids = await (await self.database.User.by_id(current_user)).chats()
        for chat_id in chat_ids:
            chat = await self.database.Chat.by_id(chat_id)
            try:
                await chat.get_current_chat_hash()
            except ValueError:
                # fails if chat is not initialized; in this case there is nothing to retrieve
                continue
            await self.kademlia.retrieve_cached_messages(chat)

    async def _chat_msg_received(self, sender: Peer, payload: ChatMsgPayload):
        sender_name = sender.ip
        sender_user = await self.database.User.register_peer(UserID(KademliaKey(sender.id)), sender.pubkey, sender_name)

        chat_id = ChatID(payload.chat_id)

        try:
            target_chat = await self.database.Chat.by_id(chat_id)
            if sender.id not in target_chat.participants:
                # chat_id collision by accident or sender tries to spoof a chat
                raise ValueError(f"SenderID is not a participant of chat {chat_id}")
            if payload.shared_secret != target_chat.secret:
                # same here for the secret
                raise ValueError(f"Chat secret does not match secret from existing chat {chat_id}")
        except KeyError:
            assert self.kademlia  # This handler is only called if kademlia node is running
            current_user = UserID(KademliaKey(self.kademlia.node_id))
            target_chat = await self.database.Chat.create(
                chat_id=chat_id,
                secret=payload.shared_secret,
                title=sender_name,
                description=f"Chat between you and {sender_name}",
                participants=[current_user, sender_user.id],
            )

        # we need to fetch this so we can calculate the message id
        last_messages = await target_chat.messages(1)
        prev_id = target_chat.secret if not last_messages else last_messages[0]
        msg_id = MessageID(msg_hash(prev_id, payload))

        # TODO: Deduplication! The same message may arrive twice => Message.create will fail
        message = await self.database.Message.create(
            id=msg_id,
            chat=target_chat.id,
            sender=sender_user.id,
            timestamp=payload.timestamp,
            content=payload.message,
            content_type=payload.content_type,
        )
        await self.sink.received_message(message)

    async def _cached_chat_msg_received(
        self,
        sender_id: KademliaKey,
        sender_pubkey: bytes,
        payload: ChatMsgPayload,
    ):
        assert self.kademlia

        chat = await self.database.Chat.by_id(ChatID(payload.chat_id))

        current_user = UserID(KademliaKey(self.kademlia.node_id))

        # Find the other chat participant
        sender_user_id = next(
            participant
            for participant in chat.participants
            if participant != current_user
        )

        sender_user = await self.database.User.by_id(sender_user_id)

        peer = Peer(
            id=KademliaKey(sender_user.id),
            ip=sender_user.name,
            pubkey=sender_pubkey,
        )

        await self._chat_msg_received(
            sender=peer,
            payload=payload,
        )
