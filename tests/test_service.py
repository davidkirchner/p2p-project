from pathlib import Path

from config import Config
from db.sqlite_impl import SqliteDatabase
from encryption import UserEncryption
from kademlia.kademlia import Peer
from models import ChatID, Message, UserID
from service import MessagingService, MessageSink
from socket_handler.inmemory import FakeNetwork, InMemorySocketHandler


class _Collector(MessageSink):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[Message] = []

    async def received_message(self, message: Message):
        self.messages.append(message)


async def _make_service(network: FakeNetwork, ident: UserEncryption, ip: str, bootstrap, sink=None):
    db = await SqliteDatabase.create(Path(":memory:"))
    # register our own identity in storage (as main/headless do before start_node)
    await ident.store_as_user(storage=db, name=ip)
    config = Config(sqlite_path=Path(":memory:"), bind_host=ip, port=9009, bootstrap_peers=bootstrap)
    service = MessagingService(
        db,
        config,
        sink=sink,
        socket_factory=lambda: InMemorySocketHandler(network),
    )
    return service, db


async def test_direct_message_delivery_between_two_services():
    network = FakeNetwork()
    boot_ident = UserEncryption.create()
    alice_ident = UserEncryption.create()
    boot_peer = Peer(id=boot_ident.id, ip="10.0.0.1", pubkey=boot_ident.public_bytes)

    boot_sink = _Collector()
    boot, _ = await _make_service(network, boot_ident, "10.0.0.1", bootstrap=(), sink=boot_sink)
    alice, _ = await _make_service(network, alice_ident, "10.0.0.2", bootstrap=(boot_peer,))

    async with boot, alice:
        await boot.start_node(boot_ident)
        await alice.start_node(alice_ident)

        chat = await alice.initialize_chat(UserID(alice_ident.id), boot_ident.id)
        status = await alice.send_message(
            UserID(alice_ident.id),
            ChatID(chat.id),
            content=b"hello boot",
            content_type="text/plain",
        )

    assert status == "delivered"
    # boot received the chat-init message and the explicit "hello boot".
    contents = {m.content for m in boot_sink.messages}
    assert b"hello boot" in contents


async def test_service_without_sink_still_delivers_and_stores():
    """A node with the default (no-op) sink must not crash on inbound messages."""
    network = FakeNetwork()
    boot_ident = UserEncryption.create()
    alice_ident = UserEncryption.create()
    boot_peer = Peer(id=boot_ident.id, ip="10.0.0.1", pubkey=boot_ident.public_bytes)

    # boot uses the default MessageSink (no sink passed)
    boot, boot_db = await _make_service(network, boot_ident, "10.0.0.1", bootstrap=())
    alice, _ = await _make_service(network, alice_ident, "10.0.0.2", bootstrap=(boot_peer,))

    async with boot, alice:
        await boot.start_node(boot_ident)
        await alice.start_node(alice_ident)

        chat = await alice.initialize_chat(UserID(alice_ident.id), boot_ident.id)
        assert await alice.send_message(
            UserID(alice_ident.id), ChatID(chat.id), content=b"hi", content_type="text/plain"
        )

        # boot created the chat and stored the message even though its sink is a
        # no-op (the handler ran end-to-end without raising).
        boot_chats = await (await boot_db.User.by_id(boot_ident.id)).chats()
        assert len(boot_chats) == 1
