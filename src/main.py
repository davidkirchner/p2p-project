import asyncio
import dotenv
from logging_setup import setup_logging

from config import Config
from db.sqlite_impl import SqliteDatabase
from ui.simple import SimpleTerminalUI, Handler as UIHandler

async def main():
    # TODO: ideally, the correct env file is passed in during program invocation.
    # Right now dev.env is hard coded. Please provide one for customization if needed
    dotenv.load_dotenv("dev.env")

    # Configure logging once, right after env files are loaded (LOG_LEVEL is read
    # from the environment). Every module just does logging.getLogger(__name__).

    setup_logging()

    config = Config.from_env()
    
    database = await SqliteDatabase.create(config.sqlite_path)

    # this context manager automatically does necessary resource management
    await SimpleTerminalUI.create_and_run_to_completion(database=database, handler=UIHandler())

if __name__ == "__main__":
    asyncio.run(main())
