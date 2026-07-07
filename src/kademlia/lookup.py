from __future__ import annotations

import asyncio
from collections import deque
from enum import Enum, auto
from typing import TYPE_CHECKING

from kademlia.types import KademliaKey

from .kademlia import ALPHA, Peer, byte_xor

if TYPE_CHECKING:
    from .kademlia import Buckets, FindValueReplyPayload, KademliaNode


class ReplyOutcome(Enum):
    STOP = auto()         # terminate the whole lookup immediately (value found)
    PROGRESS = auto()     # the k-closest set improved
    NO_PROGRESS = auto()  # reply consumed, but nothing closer was learned


class IterativeLookup[T]:
    def __init__(self, buckets: Buckets, node_id: bytes, target: KademliaKey) -> None:
        self.buckets = buckets
        self.node_id = node_id
        self.target = target
        self.nearest: dict[bytes, Peer] = {
            p.id: p for p in buckets.get_k_nearest_neighbors(target)
        }
        self.requested: set[bytes] = set()
        self.pending: set[asyncio.Task] = set()

    def _sorted(self) -> list[Peer]:
        items = sorted(self.nearest.items(), key=lambda t: byte_xor(t[0], self.target))
        return [p for _, p in items]

    def _add_peers(self, peers: list[Peer]) -> bool:
        """Merge `peers` into `self.nearest`. Returns `True` if we made progress
        (added a peer that is closer than the previous worst closest peer)"""
        before = set(self.nearest)
        for peer in peers:
            if peer.id != self.node_id:
                self.nearest[peer.id] = peer
        # keep only the k closest
        self.nearest = {p.id: p for p in self._sorted()[: self.buckets.k]}
        return set(self.nearest) != before

    def _refill(self) -> None:
        free = ALPHA - len(self.pending)
        todo = [p for p in self._sorted() if p.id not in self.requested][:free]
        for peer in todo:
            self.pending.add(asyncio.create_task(self._query_peer(peer)))
            self.requested.add(peer.id)

    def _cancel_pending(self) -> None:
        for t in self.pending:
            t.cancel()

    async def run(self) -> T:
        # Sliding window of the most recent outcomes. Once the last ALPHA
        # replies all made no progress, the search has converged.
        recent_outcomes: deque[ReplyOutcome] = deque(maxlen=ALPHA)
        self._refill()
        while self.pending:
            done, self.pending = await asyncio.wait(
                self.pending, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                try:
                    result = task.result()
                except Exception:
                    continue
                outcome = self._handle_reply(result)
                recent_outcomes.append(outcome)
                if outcome is ReplyOutcome.STOP:
                    self._cancel_pending()
                    return self._result()
            if len(recent_outcomes) == ALPHA and all(x is ReplyOutcome.NO_PROGRESS for x in recent_outcomes):
                self._cancel_pending()
                return self._result()
            self._refill()
        return self._result()

    async def _query_peer(self, peer: Peer):
        """Send the lookup's RPC to ``peer`` and return the reply."""
        raise NotImplementedError

    def _handle_reply(self, result) -> ReplyOutcome:
        """Update the candidate set from a reply and report the outcome."""
        raise NotImplementedError

    def _result(self) -> T:
        """Build the final return value."""
        raise NotImplementedError


class NodeLookup(IterativeLookup[list[Peer]]):
    def __init__(self, node: KademliaNode, target: KademliaKey) -> None:
        super().__init__(node.buckets, node.node_id, target)
        self._node = node

    async def _query_peer(self, peer: Peer):
        return await self._node._find_node_req(self.target, peer)

    def _handle_reply(self, result) -> ReplyOutcome:
        improved = self._add_peers(result or [])
        return ReplyOutcome.PROGRESS if improved else ReplyOutcome.NO_PROGRESS

    def _result(self) -> list[Peer]:
        return self._sorted()


class ValueLookup(IterativeLookup[bytes]):
    def __init__(self, node: KademliaNode, key: KademliaKey) -> None:
        super().__init__(node.buckets, node.node_id, key)
        self._key = key
        self._node = node
        self._value: bytes | None = None

    async def _query_peer(self, peer: Peer):
        return await self._node._find_value_req(peer, self.target)

    def _handle_reply(self, result: FindValueReplyPayload | None) -> ReplyOutcome:
        if result is None:
            return ReplyOutcome.NO_PROGRESS
        if result.value is not None:
            self._value = result.value
            return ReplyOutcome.STOP  # found -> stop the search
        improved = self._add_peers(result.nodes)
        return ReplyOutcome.PROGRESS if improved else ReplyOutcome.NO_PROGRESS

    def _result(self) -> bytes:
        if self._value is None:
            raise ValueError(f"Unable to find value for key {self._key} in the network")
        return self._value
