import asyncio

async def send_message(host,port,message):
    reader, writer = await asyncio.open_connection(
        host,
        port
    )

    writer.write(message)
    await writer.drain()

    print("Message sent")

    writer.close()

    await writer.wait_closed()