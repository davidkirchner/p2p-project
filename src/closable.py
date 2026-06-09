

import asyncio
from inspect import isawaitable
from typing import Awaitable, Self



async def close_thing(thing):
    if isinstance(thing, asyncio.Task):
        if not thing.done():
            thing.cancel()
            try:
                await thing
            except asyncio.CancelledError:
                pass
    elif isinstance(thing, Closable):
        await thing.close()
    else:
        return False
    
    return True


ClosableCompatible = asyncio.Task | Awaitable | Self

class Closable:
    """
    Usage:
    
    1. Inherit
    ```
    class Something(Closable):
        # dont forget to Closable.__init__(self)
    ```
    
    2. Bind some tasks or ither closables
    
    ```
    self.bind_closable(some_awaitable_function())
    self.bind_named_closable(some_other_thing(), "name_of_it")
    ```
    
    3. Use it
    
    ```
    async with Something() as s:
        # do stuff with s
        # all tasks get cancelled when the context manager exists
    ```
    
    4. manual closing:
    
    ```
    await s.close() # all gets cancelled 
    ```
        
    """
    
    def __init__(self) -> None:
        self._closed = False
        self._bound_closables = []
        self._closing_tasks = set()
    
    def bind_named_closable(self, key, value: ClosableCompatible):
        if hasattr(self, key):
            old = getattr(self, key)
            setattr(self, key, value)
            
            if not isinstance(old, asyncio.Task):
                closing_task = asyncio.create_task(close_thing(old))
            else:
                closing_task = old
                
            closing_task.add_done_callback(lambda t: self._closing_tasks.discard(t))
            self._closing_tasks.add(closing_task)
        else:
            setattr(self, key, value)
            
    def bind_closable(self, value: ClosableCompatible):
        if isinstance(value, asyncio.Task):
            task = value
            task.add_done_callback(lambda t: self._bound_closables.remove(t))
        elif isawaitable(value):
            task = asyncio.create_task(value) # type: ignore
            task.add_done_callback(lambda t: self._bound_closables.remove(t))
        elif isinstance(value, Closable):
            task = value
        else:
            raise TypeError(f"Cant bind {value}")
            
        self._bound_closables.append(task)
    
    async def close(self):
        if self._closed: return
        self._closed = True
        
        for task in list(self._closing_tasks):
            await task
            
        for value in list(self._bound_closables):
            await close_thing(value)
            
        for value in vars(self).values():
            await close_thing(value)
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc, tb):
        await self.close()