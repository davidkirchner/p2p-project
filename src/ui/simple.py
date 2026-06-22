from abc import abstractmethod
from contextlib import contextmanager, suppress
from datetime import timezone
from inspect import isawaitable
from multiprocessing import Value
import re
import sys

from textwrap import indent
from typing import Awaitable, Callable, Optional, Self
import asyncio

from closable import Closable
from config import Config
from db.sqlite_impl import SqliteDatabase
from handlers import HandlerBase
from models import *
import shlex
from aioitertools.helpers import maybe_await


from models import ChatID, UserID
    
    
class Handler(HandlerBase):
    async def send_message(self, user: UserID | None, chat: ChatID | None, content: bytes, content_type: str):
        pass
    
    async def create_user(self, name: str):
        pass
    
    async def execute_command(self, user: UserID | None, chat: ChatID | None, args: list[str]):
        pass
    



class InputParser[T]:
    @property
    def prompt(self) -> str:
        return ""
    
    @abstractmethod
    def parse(self, s) -> T:
        return s.strip()


@dataclass
class ConfirmParser(InputParser):
    default: Optional[bool] = True
    
    @property
    def prompt(self):
        match self.default:
            case True: return "[Y/n] "
            case False: return "[y/N] "
            case None: return "[y/n] "
    
    def parse(self, s) -> bool:
        s = s.strip()
        if not s: 
            if self.default is None:
                raise ValueError(f"You must choose between yes or no explicitly")
            return self.default
        if s.lower() in ("y", "yes", "ok", "1"):
            return True
        elif s.lower() in ("n", "no", "0"):
            return False
        else:
            raise SyntaxError(s)
        
        
@dataclass
class ChoiceParser[T](InputParser):
    options: list[T] | dict[str, T]
    formatter: Callable[[T], str] = str
    
    @property
    def prompt(self):
        p = "Choose between:\n"
        if isinstance(self.options, dict):
            largest_key_len = max(map(len, self.options))
            for key, value in self.options.items():
                p += f"[{key.rjust(largest_key_len)}] {self.formatter(value)}\n"
        else:
            largest_key_len = len(str(len(self.options)))
            for i, value in enumerate(self.options):
                p += f"[{str(i).rjust(largest_key_len)}] {self.formatter(value)}\n"
        return p
    
    def parse(self, s) -> T:
        s = s.strip()
        if isinstance(self.options, dict):
            return self.options[s]
        else:
            i = int(s)
            return self.options[i]
        
@dataclass
class RegexParser(InputParser):
    r: str = r"+*"
    
    @property
    def prompt(self): return ""
    
    def parse(self, s) -> str:
        s = s.strip()
        if not re.fullmatch(self.r, s):
            raise SyntaxError(f"Did not match regex {self.r}")
        return s
    
    
class Escape(Exception):
    pass

class Reset(Exception):
    pass


async def race(fs):
    done, pending = await asyncio.wait(fs, return_when=asyncio.FIRST_COMPLETED)
    for p in pending:
        p.cancel()
        with suppress(asyncio.CancelledError):
            await p
    return await done.pop()
        


class SimpleTerminalUI(Closable):
    def __init__(self, database: Storage, handler: Handler, user: UserID | None = None, chat: ChatID | None = None):
        Closable.__init__(self)
        self.database = database
        self.handler = handler
        self.chat: ChatID | None = chat
        self.user: UserID | None = user
        
        self._indent: str = ""
        self._print_indent: bool = True
        self._prompt: str = ""
        
        self._input_fut = None
        self.exit_event = asyncio.Event()
        self._state_change_condition = asyncio.Condition()
        
    @classmethod
    async def create_and_run_to_completion(cls, database: Storage, handler: Handler, user: UserID | None = None, chat: ChatID | None = None) -> Self:
        ui = cls(
            database=database,
            handler=handler,
            user=user,
            chat=chat
        )
        
        ui._ensure_terminal()
        ui.bind_closable(ui._root_view())
        await ui.exit_event.wait()
        await ui.close()
        return ui
    
    async def _print(self, message: str, end: str | None = "\n"): 
        if self._print_indent:
            print(self._indent, end=None)
            self._print_indent = message.endswith("\n") or (end is not None and end.endswith("\n"))
        print(message.replace("\n", self._indent + "\n"), flush=True, sep=None, end=end)
        
    async def _print_message(self, msg: Message):
        display_name = (await self.database.User.by_id(msg.sender)).name
        display_str = msg.content.decode("utf-8")
        await self._print(f"\r\033[K[{display_name} {msg.timestamp.time()}] {display_str}")
        
    async def _print_error(self, msg):
        await self._print(f"ERROR: {msg}")
    
    async def _root_view(self):
        while True:
            with suppress(Escape, Reset):  # only catch reset here
                if self.user is None:
                    # no user selected. select one
                    self._selectable_users = selectable_users = await self.database.User.local_profiles()
                    if not selectable_users:
                        await self._print("Hello there!")
                        await self._print("No local users exist. You should create one i guess...")
                        if not await self._input(ConfirmParser(), "Create user?"): return
                        name = await self._input(RegexParser(r"\w+"), "His name: ")
                        await self.handler.create_user(name)
                        async with self._state_change_condition:
                            await self._state_change_condition.wait_for(lambda: self.user is not None)
                    elif len(selectable_users) == 1:
                        user_data = await self.database.User.by_id(selectable_users[0])
                        await self._print(f"You are now logged in as {user_data.name}")
                    else:
                        raise NotImplementedError
                        await self._print(f"You have to select among different users:")
                        await self._print_enumerable([(await self.database.User.by_id(uid)).name for uid in selectable_users])
                        
                elif self.chat is None:
                    await self._print("Your chats:")
                    chat_ids = await (await self.database.User.by_id(self.user)).chats()
                    chat_id = await self._input(ChoiceParser(chat_ids), "Select one: ")
                    self.chat = chat_id
                else:
                    await self._messages_view()
                
    async def _messages_view(self):
        with suppress(Escape):
            msg_ids = await(await self.database.Chat.by_id(self.chat)).messages(5, before=datetime.now(tz=timezone.utc))
            last_5_messages = await asyncio.gather(*[self.database.Message.by_id(mid) for mid in msg_ids])
            for msg in last_5_messages:
                await self._print_message(msg)
            display_name = (await self.database.User.by_id(self.user)).name
            self._prompt = f"[{display_name} --:--:--.------] "
            
            while True:
                await self._print(self._prompt, end=None)
                msg = await self._input(InputParser())
                await self.send_message(msg)
    
                
                
    async def send_message(self, message: str):
        if self.chat is None:
            await self._print_error("Cannot send messages since no chat is selected.")
        self.bind_closable(self.handler.send_message(self.user, self.chat, content=message.encode("utf-8"), content_type="text/plain"))
    
    async def exit_ui(self):
        await self._print("Goodbye!")
        self.exit_event.set()

    async def escape_view(self):
        if self._input_fut:
            self._input_fut.set_exception(Escape())
            
    async def reset_view(self):
        if self._input_fut:
            self._input_fut.set_exception(Reset())
    
    
    async def _input(self, parser: InputParser, pre_prompt: str | None = None):
        if self._input_fut:
            self._input_fut.cancel()
            
        while True:
            self._input_fut = asyncio.get_running_loop().create_future()
            if pre_prompt:
                await self._print(pre_prompt, end=None)
            await self._print(parser.prompt, end=None)
            
            try:
                raw_input = await race([self._input_fut, asyncio.create_task(asyncio.to_thread(sys.stdin.readline))])
            finally:
                self._input_fut = None
                
            if raw_input.strip().lower() == "exit":
                raise Escape()
            
            if raw_input.strip().lower() == "reset":
                raise
            
            try:
                return parser.parse(raw_input)
            except (ValueError, KeyError) as e:
                await self._print(f"Bad input value: {e}")
            except SyntaxError as e:
                await self._print(f"Bad input syntax: {e}")
    
    async def _handle_raw_input(self, input: str):
        if self._input_fut:
            self._input_fut.set_result(input)
        else:
            await self._print(f"(Input not processed)")
    
    def _ensure_terminal(self) -> None:
        """Raise exception if stdin/stdout is not a real terminal."""
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise RuntimeError("Error: No terminal detected. Run this in an interactive shell.\n")

    def clear_screen(self) -> None:
        """Clear the entire terminal screen."""
        # ANSI escape works on most modern terminals (including Windows 10+)
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()