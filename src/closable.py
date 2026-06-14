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

type ClosableCompatible = asyncio.Task | Awaitable | Closable


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
    self.bind_named_closable("name_of_it", some_other_thing(),)
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
        self._bound_closables: list[ClosableCompatible] = []
        self._bound_named_closables: dict[str, ClosableCompatible] = {}
        self._closing_tasks = set()

    def bind_named_closable(self, key: str, value: ClosableCompatible):
        # Schedule bare awaitables so they actually run, mirroring bind_closable.
        if isawaitable(value) and not isinstance(value, asyncio.Task):
            value = asyncio.create_task(value) # type: ignore

        old = self._bound_named_closables.get(key)
        self._bound_named_closables[key] = value

        if old is not None:
            # Tear down the closable that was previously bound under this name.
            # close_thing() cancels Tasks and closes Closables as needed.
            closing_task = asyncio.create_task(close_thing(old))
            closing_task.add_done_callback(lambda t: self._closing_tasks.discard(t))
            self._closing_tasks.add(closing_task)

    def get_named_closable(self, key) -> ClosableCompatible | None:
        return self._bound_named_closables.get(key)

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

        for value in list(self._bound_named_closables.values()):
            await close_thing(value)

        for value in list(vars(self).values()):
            await close_thing(value)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()