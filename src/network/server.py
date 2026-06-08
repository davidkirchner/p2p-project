import asyncio
from network.transport import inbox_queue, receive_message


async def handle_client(reader,writer):
    addr = writer.get_extra_info("peername")
    sender_ip = addr[0]
    print(f"Connected with {addr}")
    data = await receive_message(reader)
    await inbox_queue.put(
        (
            sender_ip,
            data
        )
    )
    writer.close()
    await writer.wait_closed()

async def start_server(host="127.0.0.1", port=8888):
    server = await asyncio.start_server(
        handle_client,
        host,
        port
    )

    print(f"Server listening on {host}:{port}")

    async with server:
        await server.serve_forever()