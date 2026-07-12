"""Minimal Shadow simulation test.

Starts a small P2P network under the Shadow discrete-event simulator:
  * 5 bootstrap nodes (boot0 seeds, the rest join through it)
  * 10 regular peers (including alice and bob) that bootstrap off the cluster

Alice waits for the DHT to settle, sends bob a message, and bob must receive it.

Each node is `src/headless.py`, configured via environment variables and driven
by a scenario string (see that module). Nodes print `EVENT ...` lines to stdout,
which Shadow captures per host; the test asserts against bob's output.

To grow this into bigger/other tests, add hosts to the lists in
`_write_config` or change the per-host scenario strings.
"""

import base64
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest
import yaml

SRC_DIR = Path(__file__).resolve().parents[2] / "src"
HEADLESS = SRC_DIR / "headless.py"
sys.path.insert(0, str(SRC_DIR))

from encryption import UserEncryption  # noqa: E402

pytestmark = pytest.mark.skipif(
    shutil.which("shadow") is None,
    reason="shadow simulator not installed",
)

class _Dumper(yaml.SafeDumper):
    """YAML dumper that renders multi-line strings as literal `|` blocks."""


def _repr_str(dumper: yaml.Dumper, data: str) -> yaml.ScalarNode:
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_Dumper.add_representer(str, _repr_str)


# Single-node network: every host attaches to node 0 (1 Gbit links, 10ms latency).
_GRAPH_GML = dedent("""\
    graph [
      directed 0
      node [
        id 0
        host_bandwidth_down "30 Mbit"
        host_bandwidth_up "10 Mbit"
      ]
      edge [
        source 0
        target 0
        latency "100 ms"
        packet_loss 0.05
      ]
    ]
""")

_NETWORK = {"graph": {"type": "gml", "inline": _GRAPH_GML}}


def _seed(name: str) -> bytes:
    """Deterministic 32-byte Ed25519 seed from a host name."""
    return hashlib.sha256(name.encode()).digest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _pubkey_b64(name: str) -> str:
    return _b64(UserEncryption.from_seed(_seed(name)).public_bytes)


def _node_id_b64(name: str) -> str:
    return _b64(UserEncryption.from_seed(_seed(name)).id)


def _host_block(name: str, ip: str, scenario: str, start: str,
                bootstrap: list[tuple[str, str]], python_exe: str) -> dict:
    """One `hosts:` entry running headless.py with the given scenario."""
    peers = ",".join(f"{bip}={_pubkey_b64(bname)}" for bname, bip in bootstrap)
    return {
        "network_node_id": 0,
        "ip_addr": ip,
        "processes": [{
            "path": python_exe,
            "args": f"{HEADLESS} --name {name} {scenario}",
            "start_time": start,
            "expected_final_state": {"exited": 0},
            "environment": {
                "SQLITE_PATH": ":memory:",
                "BIND_HOST": "0.0.0.0",
                "KADEMLIA_PORT": "9009",
                "IDENTITY_SEED": _seed(name).hex(),
                "BOOTSTRAP_PEERS": peers,
                "PYTHONPATH": str(SRC_DIR),
                "PYTHONUNBUFFERED": "1",
            },
        }],
    }


def _write_config(tmp_path: Path, python_exe: str) -> Path:
    boots = [(f"boot{i}", f"10.0.0.{i + 1}") for i in range(5)]
    peers = [("alice", "10.0.0.6"), ("bob", "10.0.0.7")]
    peers += [(f"peer{i}", f"10.0.0.{8 + i}") for i in range(8)]

    bob_id = _node_id_b64("bob")
    hosts: dict[str, dict] = {}

    # Bootstrap cluster: boot0 seeds, the rest join through it.
    for i, (name, ip) in enumerate(boots):
        into = [] if i == 0 else [boots[0]]
        hosts[name] = _host_block(name, ip, "wait 90", "1s", into, python_exe)

    # Regular peers bootstrap against the whole cluster.
    for name, ip in peers:
        if name == "alice":
            scenario = f'wait 20 send {bob_id} "hello bob" wait 40'
        elif name == "bob":
            scenario = "recv 90"
        else:
            scenario = "wait 90"
        hosts[name] = _host_block(name, ip, scenario, "5s", boots, python_exe)

    config = {
        "general": {
            "stop_time": "120s",
            "model_unblocked_syscall_latency": True,
        },
        "network": _NETWORK,
        "hosts": hosts,
    }
    path = tmp_path / "shadow.yaml"
    path.write_text(yaml.dump(config, Dumper=_Dumper, sort_keys=False))
    return path


def _host_stdout(data_dir: Path, host: str) -> str:
    files = sorted((data_dir / "hosts" / host).glob("*.stdout"))
    assert files, f"no stdout captured for host {host!r}"
    return "\n".join(f.read_text() for f in files)


@pytest.mark.shadow
def test_alice_sends_bob_a_message(tmp_path):
    config = _write_config(tmp_path, sys.executable)
    data_dir = tmp_path / "shadow.data"

    result = subprocess.run(
        ["shadow", "--data-directory", str(data_dir), str(config)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert result.returncode == 0, f"shadow failed:\n{result.stderr[-4000:]}"

    bob_out = _host_stdout(data_dir, "bob")
    assert "EVENT recv" in bob_out, bob_out
    assert "hello bob" in bob_out, bob_out
