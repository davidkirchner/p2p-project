import asyncio
import logging
import os
import dotenv

from config import Config
from db.sqlite_impl import SqliteDatabase
from logging_setup import setup_logging
from service import MessagingService, MessageSink
from ui.simple import SimpleTerminalUI, Handler as UIHandler


async def main():
    if os.path.exists("dev.env"):
        dotenv.load_dotenv("dev.env")

    setup_logging()
    logging.getLogger(__name__)

    config = Config.from_env()
    database = await SqliteDatabase.create(config.sqlite_path)

    async with MessagingService(database, config) as service:
        ui_handler = UIHandler(
            service.send_message,
            service.create_user,
            service.selection_update,
            service.execute_command,
            service.initialize_chat,
        )
        ui: SimpleTerminalUI = await SimpleTerminalUI.create(database=database, handler=ui_handler)
        service.sink = MessageSink(ui.received_message)
        await ui.run_to_completion()


if __name__ == "__main__":
    asyncio.run(main())
