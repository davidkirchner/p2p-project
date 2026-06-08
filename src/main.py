import asyncio

from network.server import start_server
from network.transport import inbox_queue,outbox_queue,send_loop


async def inbox_processor():
    while True:
        sender_ip, message = await inbox_queue.get()

        print(
            f"Received from {sender_ip}: {message}"
        )


async def main():
    print("Starting P2P node...")

    asyncio.create_task(send_loop())
    asyncio.create_task(inbox_processor())

    # Test message
    await outbox_queue.put(
        (
            "127.0.0.1",
            8888,
            "Hello"
        )
    )

    await start_server()


if __name__ == "__main__":
    asyncio.run(main())