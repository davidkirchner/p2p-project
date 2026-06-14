import asyncio
import struct
from asyncio import StreamReader, StreamWriter
from closable import Closable

class SocketHandler(Closable):
    def __init__(self) -> None:
        super().__init__()
        self.inbox_queue = asyncio.Queue()
        self.outbox_queue = asyncio.Queue()

    async def _send_loop(self):
        while True:
            ip, port, data = await self.outbox_queue.get()

            print(f"Sending to {ip}:{port}")

            try:
                reader, writer = await asyncio.open_connection(
                    ip,
                    port,
                )

                await self._send_message(writer, data)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            except Exception as exc:
                print(f"Failed to send to {ip}:{port}: {exc!r}")

    async def _send_message(self, writer: StreamWriter, data: bytes):
        message_len = len(data)
        header = struct.pack("!I",message_len)
        writer.write(header + data)
        await writer.drain()


    async def _read_message(self, reader: StreamReader) -> bytes:
        header = await reader.readexactly(4)
        message_len = struct.unpack("!I",header)[0]
        data = await reader.readexactly(message_len)
        return data


    async def _handle_client(self, reader: StreamReader, writer: StreamWriter):
        src_ip, src_port = writer.get_extra_info("peername")
        print(f"Connected with {src_ip}:{src_port}")
        try:
            data = await self._read_message(reader)
            await self.inbox_queue.put(
                (
                    src_ip,
                    data
                )
            )
        except (asyncio.IncompleteReadError, ConnectionError) as exc:
            print(f"Failed to read from {src_ip}:{src_port}: {exc!r}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def _serve(self, server: asyncio.Server):
        async with server:
            await server.serve_forever()

    async def start(self, host="0.0.0.0", port=9009):
        # Bind the listening socket *before* returning, so callers can rely on
        # the server actually accepting connections once start() completes.
        # asyncio.start_server only resolves once the socket is bound and
        # listening; serve_forever() is kept alive as a background task.
        server = await asyncio.start_server(
            client_connected_cb=self._handle_client,
            host=host,
            port=port,
        )
        print(f"Server listening on {host}:{port}")

        self.bind_named_closable(self._send_loop.__name__, self._send_loop())
        self.bind_named_closable(self._serve.__name__, self._serve(server))
