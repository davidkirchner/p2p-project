import base64
from pathlib import Path

import pytest

from config import Config
from encryption import UserEncryption
from kademlia.kademlia import kademlia_key


# ---------------------------------------------------------------------------
# Config.from_env
# ---------------------------------------------------------------------------

class TestConfigFromEnv:
    def test_defaults_when_env_empty(self, monkeypatch):
        for var in ("SQLITE_PATH", "BIND_HOST", "KADEMLIA_PORT", "BOOTSTRAP_PEERS", "IDENTITY_SEED"):
            monkeypatch.delenv(var, raising=False)
        cfg = Config.from_env()
        assert cfg.sqlite_path == Path("db.sqlite")
        assert cfg.bind_host == "0.0.0.0"
        assert cfg.port == 9009
        assert cfg.bootstrap_peers is None
        assert cfg.identity_seed is None

    def test_reads_scalar_values(self, monkeypatch):
        monkeypatch.setenv("SQLITE_PATH", "/tmp/x.sqlite")
        monkeypatch.setenv("BIND_HOST", "10.0.0.7")
        monkeypatch.setenv("KADEMLIA_PORT", "1234")
        monkeypatch.delenv("BOOTSTRAP_PEERS", raising=False)
        monkeypatch.delenv("IDENTITY_SEED", raising=False)
        cfg = Config.from_env()
        assert cfg.sqlite_path == Path("/tmp/x.sqlite")
        assert cfg.bind_host == "10.0.0.7"
        assert cfg.port == 1234

    def test_identity_seed_hex_is_decoded(self, monkeypatch):
        seed = UserEncryption.create().private_bytes
        monkeypatch.setenv("IDENTITY_SEED", seed.hex())
        monkeypatch.delenv("BOOTSTRAP_PEERS", raising=False)
        cfg = Config.from_env()
        assert cfg.identity_seed == seed

    def test_empty_bootstrap_peers_is_empty_tuple(self, monkeypatch):
        monkeypatch.setenv("BOOTSTRAP_PEERS", "")
        cfg = Config.from_env()
        assert cfg.bootstrap_peers == ()

    def test_bootstrap_peers_parsed_with_ids_from_pubkeys(self, monkeypatch):
        a, b = UserEncryption.create(), UserEncryption.create()
        value = ",".join(
            f"{ip}={base64.b64encode(ue.public_bytes).decode()}"
            for ip, ue in (("10.0.0.1", a), ("10.0.0.2", b))
        )
        monkeypatch.setenv("BOOTSTRAP_PEERS", value)
        cfg = Config.from_env()
        assert cfg.bootstrap_peers is not None
        assert [p.ip for p in cfg.bootstrap_peers] == ["10.0.0.1", "10.0.0.2"]
        # id must be sha256(pubkey) so it matches the peer's real identity
        assert cfg.bootstrap_peers[0].id == kademlia_key(a.public_bytes)
        assert cfg.bootstrap_peers[0].pubkey == a.public_bytes

    def test_malformed_bootstrap_peer_raises(self, monkeypatch):
        monkeypatch.setenv("BOOTSTRAP_PEERS", "10.0.0.1")  # missing '=<pubkey>'
        with pytest.raises(ValueError):
            Config.from_env()


# ---------------------------------------------------------------------------
# UserEncryption.from_seed (deterministic identity)
# ---------------------------------------------------------------------------

class TestFromSeed:
    def test_same_seed_gives_same_identity(self):
        seed = UserEncryption.create().private_bytes
        a = UserEncryption.from_seed(seed)
        b = UserEncryption.from_seed(seed)
        assert a.id == b.id
        assert a.public_bytes == b.public_bytes

    def test_seed_round_trips_through_private_bytes(self):
        seed = UserEncryption.create().private_bytes
        assert UserEncryption.from_seed(seed).private_bytes == seed

    def test_id_is_sha256_of_pubkey(self):
        ue = UserEncryption.from_seed(UserEncryption.create().private_bytes)
        assert ue.id == kademlia_key(ue.public_bytes)

    def test_different_seeds_give_different_identities(self):
        a = UserEncryption.from_seed(UserEncryption.create().private_bytes)
        b = UserEncryption.from_seed(UserEncryption.create().private_bytes)
        assert a.id != b.id
