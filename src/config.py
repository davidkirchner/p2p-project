import base64
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self

from kademlia.kademlia import Peer, kademlia_key


@dataclass(unsafe_hash=True)
class Config:

    sqlite_path: Path
    bind_host: str = "0.0.0.0"
    port: int = 9009
    bootstrap_peers: tuple[Peer, ...] | None = field(default=None, hash=False)
    # 32-byte Ed25519 seed for a deterministic identity, or None for a random one.
    identity_seed: bytes | None = None

    @classmethod
    def from_env(cls, prefix: str = "") -> Self:
        def env(name: str) -> str | None:
            return os.environ.get(prefix + name)

        path_str = env("SQLITE_PATH")
        sqlite_path = Path(path_str) if path_str is not None else Path("db.sqlite")

        bind_host = env("BIND_HOST") or "0.0.0.0"

        port_str = env("KADEMLIA_PORT")
        port = int(port_str) if port_str else 9009

        bootstrap_peers = cls._parse_bootstrap_peers(env("BOOTSTRAP_PEERS"))

        seed_str = env("IDENTITY_SEED")
        identity_seed = bytes.fromhex(seed_str) if seed_str else None

        return cls(
            sqlite_path=sqlite_path,
            bind_host=bind_host,
            port=port,
            bootstrap_peers=bootstrap_peers,
            identity_seed=identity_seed,
        )

    @staticmethod
    def _parse_bootstrap_peers(value: str | None) -> tuple[Peer, ...] | None:
        """Parse `"ip=<b64 pubkey>,ip=<b64 pubkey>"` into Peers."""
        if value is None:
            return None
        entries = [e.strip() for e in value.split(",") if e.strip()]
        peers: list[Peer] = []
        for entry in entries:
            ip, eq_sign, pubkey_b64 = entry.partition("=")
            ip = ip.strip()
            if not eq_sign or not ip or not pubkey_b64.strip():
                raise ValueError(f"Invalid bootstrapping peers entry: {entry!r} (expected 'ip=<b64 pubkey>')")
            pubkey = base64.b64decode(pubkey_b64.strip())
            peers.append(Peer(id=kademlia_key(pubkey), ip=ip, pubkey=pubkey))
        return tuple(peers)
