import asyncio

async def handle_client(reader,writer):
    addr = writer.get_extra_info("peername")
    print(f"Connected with {addr}")
    data = await reader.read(100)
    message = data.decode()
    print("Received:", message)
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