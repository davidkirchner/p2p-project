import asyncio

from client import send_message

async def main():
    await send_message(
        "127.0.0.1",
        8888,
        b'Hello dear server'
    )

asyncio.run(main())