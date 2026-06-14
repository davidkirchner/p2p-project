import asyncio

from closable import Closable


async def _forever() -> None:
    """A coroutine that never finishes on its own (only via cancellation)."""
    await asyncio.sleep(3600)


async def _wait_done(task: asyncio.Task, timeout: float = 1.0) -> None:
    """Let the loop run until ``task`` is done, failing fast on a hang."""
    await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), timeout)


# Binding a name must not shadow an instance method of the same name: the task
# goes into the registry, the method stays callable.
async def test_bind_named_does_not_overwrite_method():
    class Node(Closable):
        async def recv_loop(self):
            await _forever()

    node = Node()
    task = asyncio.create_task(node.recv_loop())
    node.bind_named_closable("recv_loop", task)

    assert callable(node.recv_loop)
    assert not isinstance(node.recv_loop, asyncio.Task)
    assert node.get_named_closable("recv_loop") is task

    await node.close()
    assert task.cancelled()


# Same for a plain attribute: it must survive, only the registry holds the task.
async def test_bind_named_does_not_overwrite_plain_attribute():
    node = Closable()
    node.value = 42  # type: ignore[attr-defined]
    node.bind_named_closable("value", asyncio.create_task(_forever()))

    assert node.value == 42  # type: ignore[attr-defined]
    assert isinstance(node.get_named_closable("value"), asyncio.Task)

    await node.close()


# close() tears down whatever was bound under a name.
async def test_close_tears_down_named_closables():
    node = Closable()
    node.bind_named_closable("loop", asyncio.create_task(_forever()))
    task = node.get_named_closable("loop")
    assert isinstance(task, asyncio.Task) and not task.done()

    await node.close()
    assert task.done()


# Re-binding a name cancels the task that was previously bound there (it used to
# be awaited but never cancelled).
async def test_rebind_named_cancels_previous_task():
    node = Closable()
    old = asyncio.create_task(_forever())
    node.bind_named_closable("loop", old)

    new = asyncio.create_task(_forever())
    node.bind_named_closable("loop", new)

    # The cleanup of the old task is scheduled; let the loop drain it.
    await _wait_done(old)
    assert old.cancelled()
    assert not new.done()
    assert node.get_named_closable("loop") is new

    await node.close()
    assert new.cancelled()


# Even if close() runs before the scheduled rebind-cleanup got a chance to run,
# close() must still wait for it.
async def test_close_awaits_scheduled_replacement_cleanup():
    node = Closable()
    old = asyncio.create_task(_forever())
    node.bind_named_closable("loop", old)
    new = asyncio.create_task(_forever())
    node.bind_named_closable("loop", new)

    # Do not give the scheduled cleanup time to run; close() must still cover it.
    await node.close()
    assert old.cancelled()
    assert new.cancelled()


# A bare coroutine bound by name is wrapped into a Task and actually runs
async def test_bind_named_schedules_awaitable_on_first_bind():
    started = asyncio.Event()

    async def work():
        started.set()
        await _forever()

    node = Closable()
    node.bind_named_closable("w", work())  # pass a raw coroutine, not a Task

    bound = node.get_named_closable("w")
    assert isinstance(bound, asyncio.Task)  # wrapped into a Task...
    await asyncio.wait_for(started.wait(), 1.0)  # ...and actually runs

    await node.close()
    assert bound.cancelled()


# An already-created Task is stored unchanged (not re-wrapped).
async def test_bind_named_keeps_existing_task_as_is():
    node = Closable()
    task = asyncio.create_task(_forever())
    node.bind_named_closable("w", task)

    assert node.get_named_closable("w") is task

    await node.close()
    assert task.cancelled()
