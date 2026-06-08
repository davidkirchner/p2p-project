if __name__ == "__main__":
    import asyncio

    import dotenv

    # TODO: ideally, the correct env file is passed in during program invocation.
    # Right now dev.env is hard coded. Please provide one for customization if needed
    dotenv.load_dotenv("dev.env")

    # Configure logging once, right after env files are loaded (LOG_LEVEL is read
    # from the environment). Every module just does logging.getLogger(__name__).
    from logging_setup import setup_logging

    setup_logging()

    from ui.simple import main

    asyncio.run(main())
