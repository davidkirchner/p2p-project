from functools import partial
import sys
import os

from contextlib import closing
import threading
import time
from typing import Callable, List, Self
import asyncio

from config import Config
from db.sqlite_impl import SqliteDatabase
from models import *

class SimpleTerminalUI:
    def __init__(self, database: Context, incoming_events: asyncio.Queue, outgoing_events: asyncio.Queue, user: UserID, current_chat: ChatID | None = None):
        self.database = database
        self.incoming_events = incoming_events
        self.outgoing_events = outgoing_events
        self.current_chat = current_chat
        self.user = user
        
        self.exit_event = asyncio.Event()
        
        self._bound_tasks = {}
        
    @classmethod
    async def create_and_start(cls, database: Context, incoming_events: asyncio.Queue, user: UserID) -> Self:
        ui = cls(
            database=database,
            incoming_events=incoming_events,
            outgoing_events=asyncio.Queue(),
            user=user
        )
        ui._bind_task(asyncio.create_task(input_loop(lambda i: ui._bind_task(asyncio.create_task(ui._handle_raw_input(i))))), "input_loop")
        ui._bind_task(asyncio.create_task(ui._handle_incoming_message_loop()), "handle_incoming_message_loop")
        await ui.handle_chat(None)
        return ui
    
    def _bind_task(self, task: asyncio.Task, name: str | asyncio.Task | None = None):
        if name is None:
            name = task
            
        if name in self._bound_tasks:
            old_task = self._bound_tasks.pop(name)
            old_task.cancel()
        
        self._bound_tasks[name] = task
        
        def remove(t):
            current_task = self._bound_tasks.get(name, None)
            if current_task is None:
                return
            if current_task == t:
                del self._bound_tasks[name]
                
        task.add_done_callback(remove)
    
    async def _handle_raw_input(self, input: str):
        if input == "exit\n":
            self.exit_event.set()
            return
        
        assert self.current_chat
        assert isinstance(self.database, SqliteDatabase)
        
        msg = await self.database.create_message( 
            chat=self.current_chat, 
            sender=self.user, 
            content=input.strip().encode("utf-8"), 
            content_type="text/plain"
        )
        self.outgoing_events.put_nowait(msg)
        await self.handle_message(msg)
        
    async def _handle_incoming_message_loop(self):
        while True:
            res = await self.incoming_events.get()
            self._bind_task(asyncio.create_task(self._handle_incoming_message(res)))
        
    async def _handle_incoming_message(self, message):
        pass # todo implement this
    
    def _ensure_terminal(self) -> None:
        """Raise exception if stdin/stdout is not a real terminal."""
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise RuntimeError("Error: No terminal detected. Run this in an interactive shell.\n")

    def clear_screen(self) -> None:
        """Clear the entire terminal screen."""
        # ANSI escape works on most modern terminals (including Windows 10+)
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
    
    async def handle_chat(self, chat: ChatID | None):
        self.current_chat = chat
        self.clear_screen()
        
        if chat is None:
            self._print_start_screen()
            await self._print_prompt()
            return
        
        last_messages = await (await self.database.Chat.by_id(chat)).messages(n=5, before=datetime.now(tz=None))
        for msg_id in last_messages:
            msg = await self.database.Message.by_id(msg_id)
            await self._print_message(msg)
        await self._print_prompt()

    async def handle_message(self, msg: Message):
        if msg.sender == self.user:
            print("\033[F", end="")  # move cursor up one line
            await self._print_message(msg)
        else:
            await self._print_message(msg)
        await self._print_prompt()
        
    async def _print_message(self, msg: Message):
        display_name = (await self.database.User.by_id(msg.sender)).name
        display_str = msg.content.decode("utf-8")
        print("\r\033[K", end="")
        print(f"[{display_name} {msg.timestamp.time()}] {display_str}")
        
    async def _print_prompt(self):
        display_name = (await self.database.User.by_id(self.user)).name
        print(f"[{display_name} --:--:--.------] ", end="", flush=True) 
        
    def _print_start_screen(self):
        print("Hello there! Welcome to chat")
        
    async def close(self):
        for task in list(self._bound_tasks.values()):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        


async def input_loop(handle_input: Callable[[str], None]):
    while True:
        result = await asyncio.to_thread(sys.stdin.readline)
        handle_input(result)


async def main() -> None:
    events = asyncio.Queue()
    config = Config.from_env()
    database = await SqliteDatabase.create(config.sqlite_path)
    ui = None
    
    try:
        alice = await database.User.by_id("user/alice")
        chat = (await alice.chats())[0]
        
        ui = await SimpleTerminalUI.create_and_start(database=database, incoming_events=events, user=alice.id)
        await ui.handle_chat(chat)
                
        await ui.exit_event.wait()
    finally:
        if ui:
            await ui.close()


if __name__ == "__main__":
    asyncio.run(main())