import uuid
from datetime import datetime, timedelta, timezone

import pytest

import models as m
from kademlia.types import KademliaKey
from db.sqlite_impl import SqliteDatabase


# ---------------------------------------------------------------------------
# fixtures & helpers
# ---------------------------------------------------------------------------

@pytest.fixture
async def db(tmp_path) -> SqliteDatabase:
    """A fresh, file-backed database in an isolated temp dir per test."""
    return await SqliteDatabase.create(tmp_path / "test.db")


def _uid(n: int = 1) -> m.UserID:
    """A deterministic 32-byte user id."""
    return m.UserID(KademliaKey(bytes([n]) * 32))


def _cid() -> m.ChatID:
    """Random 16-byte chat id."""
    return m.ChatID(uuid.uuid4().bytes)


def _mid(n: int = 1) -> m.MessageID:
    """Deterministic 16-byte message id."""
    return m.MessageID(bytes([n]) * 16)


async def _make_user(db: SqliteDatabase, n: int = 1, name: str = "alice") -> m.User:
    return await db.User.create(_uid(n), name)


async def _make_chat(db: SqliteDatabase, chat_id: m.ChatID | None = None, participants=None) -> m.Chat:
    return await db.Chat.create(
        chat_id=chat_id if chat_id is not None else _cid(),
        secret=b"s3cret",
        title="general",
        description="a room",
        participants=participants,
    )


# ===========================================================================
# User
# ===========================================================================

async def test_user_create_then_read_roundtrips_all_fields(db: SqliteDatabase):
    uid = _uid(1)
    await db.User.create(
        uid, "alice", public_identity=b"\x01pub", private_identity=b"\x02priv"
    )

    fetched = await db.User.by_id(uid)

    assert fetched.id == uid
    assert fetched.name == "alice"
    assert fetched.public_identity == b"\x01pub"
    assert fetched.private_identity == b"\x02priv"


async def test_user_by_id_missing_raises_keyerror(db: SqliteDatabase):
    with pytest.raises(KeyError):
        await db.User.by_id(_uid(99))


async def test_user_save_updates_fields(db: SqliteDatabase):
    uid = _uid(1)
    user = await db.User.create(uid, "alice")

    user.name = "alice-renamed"
    user.public_identity = b"new-pub"
    user.private_identity = b"new-priv"
    await user.save()

    fetched = await db.User.by_id(uid)
    assert fetched.name == "alice-renamed"
    assert fetched.public_identity == b"new-pub"
    assert fetched.private_identity == b"new-priv"


async def test_user_delete_removes_user(db: SqliteDatabase):
    uid = _uid(1)
    user = await db.User.create(uid, "alice")

    await user.delete()

    with pytest.raises(KeyError):
        await db.User.by_id(uid)


async def test_register_peer_stores_public_only(db: SqliteDatabase):
    uid = _uid(5)
    await db.User.register_peer(uid, public_identity=b"peer-pub", name="bob")

    fetched = await db.User.by_id(uid)
    assert fetched.public_identity == b"peer-pub"
    # A remote peer has no private identity (stored NULL -> normalised to b"").
    assert fetched.private_identity == b""


async def test_register_peer_is_idempotent(db: SqliteDatabase):
    uid = _uid(5)
    await db.User.register_peer(uid, public_identity=b"first", name="bob")

    # Second call for the same id must not raise and must not overwrite.
    again = await db.User.register_peer(uid, public_identity=b"second", name="other")

    assert again.public_identity == b"first"
    assert again.name == "bob"


async def test_local_profiles_lists_only_owned_identities(db: SqliteDatabase):
    owned = _uid(1)
    peer = _uid(2)
    await db.User.create(owned, "me", private_identity=b"my-key")
    await db.User.register_peer(peer, public_identity=b"pub", name="remote")

    profiles = await db.User.local_profiles()

    assert owned in profiles
    assert peer not in profiles
    assert len(profiles) == 1


async def test_user_chats_lists_joined_chats(db: SqliteDatabase):
    user = await _make_user(db, 1)
    other = await _make_user(db, 2, name="bob")
    cid = _cid()
    await db.Chat.create(
            chat_id=cid,
            secret=b"s3cret",
            title="general",
            description="a room",
            participants=[user.id, other.id],
        )

    assert await user.chats() == [cid]


async def test_user_chats_empty_when_not_participating(db: SqliteDatabase):
    user = await _make_user(db)

    assert await user.chats() == []


# ===========================================================================
# Chat
# ===========================================================================

async def test_chat_create_then_read_roundtrips_all_fields(db: SqliteDatabase):
    cid = _cid()
    await db.Chat.create(
        chat_id=cid, secret=b"top-secret", title="ops", description="the ops room"
    )

    fetched = await db.Chat.by_id(cid)

    assert fetched.id == cid
    assert fetched.secret == b"top-secret"
    assert fetched.title == "ops"
    assert fetched.description == "the ops room"


async def test_chat_create_persists_participants(db: SqliteDatabase):
    await _make_user(db, 1)
    await _make_user(db, 2, name="bob")
    cid = _cid()

    await _make_chat(db, chat_id=cid, participants=[_uid(1), _uid(2)])

    fetched = await db.Chat.by_id(cid)
    assert set(fetched.participants) == {_uid(1), _uid(2)}


async def test_chat_by_id_missing_raises_keyerror(db: SqliteDatabase):
    with pytest.raises(KeyError):
        await db.Chat.by_id(_cid())


async def test_chat_save_updates_scalar_fields(db: SqliteDatabase):
    cid = _cid()
    chat = await _make_chat(db, chat_id=cid)

    chat.title = "renamed"
    chat.description = "new desc"
    chat.secret = b"rotated"
    await chat.save()

    fetched = await db.Chat.by_id(cid)
    assert fetched.title == "renamed"
    assert fetched.description == "new desc"
    assert fetched.secret == b"rotated"


async def test_chat_save_syncs_participants(db: SqliteDatabase):
    await _make_user(db, 1)
    await _make_user(db, 2, name="bob")
    cid = _cid()
    chat = await _make_chat(db, chat_id=cid, participants=[_uid(1)])

    chat.participants = [_uid(2)]
    await chat.save()

    fetched = await db.Chat.by_id(cid)
    assert fetched.participants == [_uid(2)]


async def test_chat_delete_removes_chat(db: SqliteDatabase):
    cid = _cid()
    chat = await _make_chat(db, chat_id=cid)

    await chat.delete()

    with pytest.raises(KeyError):
        await db.Chat.by_id(cid)


async def test_chat_delete_cascades_to_messages(db: SqliteDatabase):
    user = await _make_user(db)
    chat = await _make_chat(db, participants=[user.id])
    mid = _mid(1)
    await db.Message.create(
        id=mid,
        chat=chat.id,
        sender=user.id,
        timestamp=datetime.now(tz=timezone.utc),
        content=b"hi",
    )

    await chat.delete()

    with pytest.raises(KeyError):
        await db.Message.by_id(mid)


# ---------------------------------------------------------------------------
# Chat.messages: paging & ordering
# ---------------------------------------------------------------------------

async def _seed_messages(db: SqliteDatabase, chat: m.Chat, user: m.User, base: datetime, count: int):
    """Create ``count`` messages, one minute apart, oldest first."""
    for i in range(count):
        await db.Message.create(
            id=_mid(i + 1),
            chat=chat.id,
            sender=user.id,
            timestamp=base + timedelta(minutes=i),
            content=f"msg-{i}".encode(),
        )


async def test_chat_messages_returns_newest_first(db: SqliteDatabase):
    user = await _make_user(db)
    chat = await _make_chat(db, participants=[user.id])
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    await _seed_messages(db, chat, user, base, count=3)

    ids = await chat.messages(n=10)

    # Newest (highest timestamp) first: _mid(3), _mid(2), _mid(1).
    assert ids == [_mid(3), _mid(2), _mid(1)]


async def test_chat_messages_respects_limit(db: SqliteDatabase):
    user = await _make_user(db)
    chat = await _make_chat(db, participants=[user.id])
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    await _seed_messages(db, chat, user, base, count=5)

    ids = await chat.messages(n=2)

    assert ids == [_mid(5), _mid(4)]


async def test_chat_messages_respects_before_cutoff(db: SqliteDatabase):
    user = await _make_user(db)
    chat = await _make_chat(db, participants=[user.id])
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    await _seed_messages(db, chat, user, base, count=3)

    # Cutoff at base+90s: messages at base+0m and base+1m qualify, base+2m does not.
    ids = await chat.messages(n=10, before=base + timedelta(seconds=90))

    assert ids == [_mid(2), _mid(1)]


async def test_chat_messages_empty_for_new_chat(db: SqliteDatabase):
    chat = await _make_chat(db)

    assert await chat.messages(n=10) == []


# ===========================================================================
# Message
# ===========================================================================

async def test_message_create_then_read_roundtrips_all_fields(db: SqliteDatabase):
    user = await _make_user(db)
    chat = await _make_chat(db, participants=[user.id])
    ts = datetime(2026, 7, 6, 12, 30, tzinfo=timezone.utc)
    mid = _mid(1)

    await db.Message.create(
        id=mid,
        chat=chat.id,
        sender=user.id,
        timestamp=ts,
        content=b"\x00binary\xff",
        content_type="text/plain",
    )

    fetched = await db.Message.by_id(mid)
    assert fetched.id == mid
    assert fetched.chat == chat.id
    assert fetched.sender == user.id
    assert fetched.timestamp == ts
    assert fetched.content == b"\x00binary\xff"
    assert fetched.content_type == "text/plain"


async def test_message_by_id_missing_raises_keyerror(db: SqliteDatabase):
    with pytest.raises(KeyError):
        await db.Message.by_id(_mid(99))


async def test_message_save_updates_fields(db: SqliteDatabase):
    user = await _make_user(db)
    chat = await _make_chat(db, participants=[user.id])
    mid = _mid(1)
    msg = await db.Message.create(
        id=mid,
        chat=chat.id,
        sender=user.id,
        timestamp=datetime.now(tz=timezone.utc),
        content=b"before",
    )

    msg.content = b"after"
    msg.content_type = "text/markdown"
    await msg.save()

    fetched = await db.Message.by_id(mid)
    assert fetched.content == b"after"
    assert fetched.content_type == "text/markdown"


async def test_message_delete_removes_message(db: SqliteDatabase):
    user = await _make_user(db)
    chat = await _make_chat(db, participants=[user.id])
    mid = _mid(1)
    msg = await db.Message.create(
        id=mid,
        chat=chat.id,
        sender=user.id,
        timestamp=datetime.now(tz=timezone.utc),
        content=b"bye",
    )

    await msg.delete()

    with pytest.raises(KeyError):
        await db.Message.by_id(mid)
