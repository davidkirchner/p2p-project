dummy_var = 42
import asyncio

from network.server import start_server

async def main():
    print("Starting P2P node...")

    await start_server()


if __name__ == "__main__":
    asyncio.run(main())
