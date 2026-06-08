import asyncio, transport

async def send_to_peer(host,port,message):
    reader, writer = await asyncio.open_connection(
        host,
        port
    )

    await transport.send_message(writer,message)
    print("Message sent")
    writer.close()
    await writer.wait_closed()