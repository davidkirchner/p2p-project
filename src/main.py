import asyncio
import dotenv
from logging_setup import setup_logging

from config import Config
from db.sqlite_impl import SqliteDatabase
from ui.simple import SimpleTerminalUI

async def main():
    # TODO: ideally, the correct env file is passed in during program invocation.
    # Right now dev.env is hard coded. Please provide one for customization if needed
    dotenv.load_dotenv("dev.env")

    # Configure logging once, right after env files are loaded (LOG_LEVEL is read
    # from the environment). Every module just does logging.getLogger(__name__).

    setup_logging()

    events = asyncio.Queue()
    config = Config.from_env()
    database = await SqliteDatabase.create(config.sqlite_path)
    ui = None
    
    
    # create some example user to play with
    # bob actually never responds
    # TODO: implement actual user creation and stuff over the prompt line
    try:
        alice = await database.User.by_id("user/alice")
        chat_id = (await alice.chats())[0]
    except KeyError:
        alice = await database.User.create("Alice")
        bob = await database.User.create("Bob")
        chat = await database.Chat.create("TEst chat", participants=[alice.id, bob.id])
        message = await database.Message.create(chat.id, bob.id, b"whatsup")
        chat_id = chat.id
    
    # this context manager automatically does necessary resource management
    async with await SimpleTerminalUI.create_and_start(database=database, incoming_events=events, user=alice.id) as ui:
        await ui.display_chat(chat_id)
        try:
            await ui.exit_event.wait()
        except (KeyboardInterrupt, asyncio.CancelledError):
            exit(0)

if __name__ == "__main__":
    asyncio.run(main())
