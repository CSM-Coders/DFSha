"""pruebas unitarias del planificador de bloques (no necesitan el cluster)"""
import sys
import time
import collections
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "control_node"))

import app  # noqa: E402
from fastapi import HTTPException  # noqa: E402

MB = 1024 * 1024


def _set_nodes(loads: dict[str, int]):
    app.DATANODES.clear()
    for nid, used in loads.items():
        app.DATANODES[nid] = {"address": f"{nid}:1", "internal_address": f"{nid}:1",
                              "used_bytes": used, "last_seen": time.time()}


def _spread(blocks):
    c = collections.Counter(n for b in blocks for n in b["nodes"])
    for b in blocks:
        assert len(set(b["nodes"])) == len(b["nodes"]) == min(app.REPLICATION_FACTOR, 3)
    return c


def test_equal_nodes_get_even_spread():
    _set_nodes({"a": 0, "b": 0, "c": 0})
    blocks = app._plan_blocks(60 * 4 * MB, 4 * MB)
    c = _spread(blocks)
    assert len(blocks) == 60 and sum(c.values()) == 120
    assert min(c.values()) >= 30, c  # ideal: 40 cada uno


def test_similar_loads_are_treated_as_equal():
    _set_nodes({"a": 10 * MB, "b": 50 * MB, "c": 90 * MB})  # misma franja de 128 mb
    c = _spread(app._plan_blocks(60 * 4 * MB, 4 * MB))
    assert set(c) == {"a", "b", "c"} and min(c.values()) >= 25, c


def test_heavily_loaded_node_is_avoided():
    _set_nodes({"a": 0, "b": 0, "c": 900 * MB})
    c = _spread(app._plan_blocks(10 * 4 * MB, 4 * MB))
    assert c["c"] == 0, c


def test_last_block_size_and_empty_file():
    _set_nodes({"a": 0, "b": 0, "c": 0})
    blocks = app._plan_blocks(10 * MB, 4 * MB)
    assert [b["size"] for b in blocks] == [4 * MB, 4 * MB, 2 * MB]
    empty = app._plan_blocks(0, 4 * MB)
    assert len(empty) == 1 and empty[0]["size"] == 0


def test_degraded_when_fewer_nodes_than_factor_and_rejected_when_none():
    _set_nodes({"a": 0})
    assert all(len(b["nodes"]) == 1 for b in app._plan_blocks(8 * MB, 4 * MB))
    _set_nodes({})
    with pytest.raises(HTTPException) as e:
        app._plan_blocks(8 * MB, 4 * MB)
    assert e.value.status_code == 503


def test_password_hashing():
    h = app._hash_password("clave-123")
    assert h.startswith("scrypt$") and "clave-123" not in h
    assert app._verify_password("clave-123", h)
    assert not app._verify_password("otra", h)
    assert not app._verify_password("x", None)
    assert app._hash_password("clave-123") != h  # sal distinta en cada hash


def test_path_normalization():
    assert app._norm("/a//b/../c/") == "/a/c"
    assert app._norm("//x") == "/x"
    assert app._norm("/") == "/"
    for bad in ("", "relativo", "a/b"):
        with pytest.raises(HTTPException):
            app._norm(bad)
