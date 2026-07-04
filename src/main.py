import asyncio
from datetime import datetime, timezone
import itertools
from mimetypes import init
import secrets
from typing import cast
import dotenv
from encryption import UserEncryption
from kademlia.kademlia import ChatMsgPayload, KademliaNode, kademlia_key, Handler as KademliaHandler
from kademlia.types import KademliaKey
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
    
    async def send_message(user: UserID, chat: ChatID, content: bytes, content_type: str):
        if not kademlia: return
        assert content_type == "text/plain"
        
        participants = (await database.Chat.by_id(chat)).participants
        others = [p for p in participants if p != user]
        assert len(others) == 1
        target_peer_id = (await database.User.by_id(others[0])).id
        
        if not await kademlia.chat_msg_req(peer_id=target_peer_id, chat_id=chat, message=content, content_type=content_type):
            raise RuntimeError(f"Message could not be sent in time")
        
    
    async def chat_msg_received(sender_key: KademliaKey, payload: ChatMsgPayload):
        sender = (await database.User.by_id(sender_key))
        sender_name = cast(str, sender.name or sender.id)
        
        chat_id = ChatID(payload.chat_id)
        
        try:
            target_chat = await database.Chat.by_id(chat_id)
        except KeyError:
            await ui.wait_for(lambda: ui.user)
            current_user = cast(UserID, ui.user)
            raise NotImplementedError  # TODO: we first need to receive the chat secret before establishing a chat
            target_chat = await database.Chat.create(secret=chat_secret, title=sender_name, description=f"Chat between you and {sender_name}", participants=[current_user, sender.id])

        msg_id = MessageID(secrets.token_bytes(32))  # TODO: instead of random, make it based on the hash of the contents etc.
        ts = datetime.now(tz=timezone.utc)  # TODO: we need the timestamp from the other user! When it was sent, not received
        message = await database.Message.create(id=msg_id, chat=target_chat.id, sender=sender.id, timestamp=ts, content=payload.message, content_type=payload.content_type)
        await ui.received_message(message)
        
    
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
    
    async def conntect_to(self: UserID, peer_id: KademliaKey) -> Chat:
        assert kademlia
        peer = await kademlia.resolve_peer(peer_id)
        timeout = 10.0
        if not await kademlia.ping(peer_id=peer_id, timeout=timeout):
            raise TimeoutError(f"Peer didn't react in {timeout} seconds")
        
        # i guess we can create a chat now and call it a day?
        peer_name = str(peer.ip) # TODO: fetch metadata about other peer
        chat_secret = ChatID(secrets.token_bytes(32)) # we create a random (important!) chat secret
        target_chat = await database.Chat.create(secret=chat_secret, title=peer_name, description=f"Chat between you and {peer_name}", participants=[self, UserID(peer_id)])
        return target_chat

    # this context manager automatically does necessary resource management
    ui_handler = UIHandler(
        send_message,
        create_user,
        selection_update,
        execute_command,
        conntect_to
    )
    ui: SimpleTerminalUI = await SimpleTerminalUI.create(database=database, handler=ui_handler)
    await ui.run_to_completion()

if __name__ == "__main__":
    asyncio.run(main())
