import asyncio
import struct

#outbox queue
#inbox queue
#send loop
#framing (later)

outbox_queue = asyncio.Queue()
inbox_queue = asyncio.Queue()

async def send_loop():
    while True:
        ip, port, data = await outbox_queue.get()

        print(f"Sending to {ip}:{port}")

        reader,writer = await asyncio.open_connection(
            ip,
            port,
        )

        await send_message(writer, data)

        await writer.drain()

        writer.close()

        await writer.wait_closed()

async def send_message(writer,data):
    encoded_data = data.encode()
    message_len = len(encoded_data)
    header = struct.pack("!I",message_len) 
    writer.write(header + encoded_data)
    await writer.drain()

    
async def receive_message(reader):
    header = await reader.readexactly(4)
    message_len = struct.unpack("!I",header)[0]
    data = await reader.readexactly(message_len)
    return data.decode()
