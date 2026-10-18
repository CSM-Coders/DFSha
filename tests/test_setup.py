"""arranque limpio y recuperación de la pki, sin docker ni acceso a la red"""
import importlib.util
import os
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prepare = load_script("prepare_local")
certs = load_script("gen_certs")


def test_new_setup_generates_private_unique_secrets_without_printing(tmp_path, capsys):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    assert prepare.prepare_env(first, admin=True)
    assert prepare.prepare_env(second)
    prepare.validate_env(first / ".env")
    prepare.validate_env(second / ".env")
    before = (first / ".env").read_bytes()
    assert before != (second / ".env").read_bytes()
    assert len(next(line.split("=", 1)[1] for line in before.decode().splitlines()
                    if line.startswith("ADMIN_PASSWORD="))) >= 24
    assert not capsys.readouterr().out
    if os.name != "nt":
        assert (first / ".env").stat().st_mode & 0o777 == 0o600


def test_valid_env_and_data_are_preserved_without_rotating_secret(tmp_path):
    prepare.prepare_env(tmp_path)
    before = (tmp_path / ".env").read_bytes()
    (tmp_path / "data").mkdir()
    block = tmp_path / "data" / "example.blk"
    block.write_bytes(b"encrypted-data")
    assert not prepare.prepare_env(tmp_path, existing_data=True, admin=True)
    assert (tmp_path / ".env").read_bytes() == before
    assert block.read_bytes() == b"encrypted-data"


def test_exported_secret_cannot_silently_override_the_saved_key(tmp_path, monkeypatch):
    prepare.prepare_env(tmp_path)
    before = (tmp_path / ".env").read_bytes()
    monkeypatch.setenv("CLUSTER_SECRET", "dfsha-dev-secret-change-me")
    with pytest.raises(prepare.SetupError, match="entorno no coincide"):
        prepare.prepare_env(tmp_path)
    assert (tmp_path / ".env").read_bytes() == before
    monkeypatch.setenv("CLUSTER_SECRET", prepare.validate_env(tmp_path / ".env"))
    assert not prepare.prepare_env(tmp_path)


@pytest.mark.parametrize("value", ["", "dfsha-dev-secret-change-me", "cambia-esto-por-un-secreto-largo-y-aleatorio",
                                  "a" * 64, "${CLUSTER_SECRET}"])
def test_invalid_existing_env_is_rejected_without_exposing_or_replacing_secret(tmp_path, value):
    env = tmp_path / ".env"
    before = f"CLUSTER_SECRET={value}\n".encode()
    env.write_bytes(before)
    with pytest.raises(prepare.SetupError) as caught:
        prepare.prepare_env(tmp_path)
    assert env.read_bytes() == before
    if value:
        assert value not in str(caught.value)


def test_missing_env_with_data_never_generates_a_replacement_key(tmp_path):
    with pytest.raises(prepare.SetupError, match="original"):
        prepare.prepare_env(tmp_path, existing_data=True)
    assert not (tmp_path / ".env").exists()
    (tmp_path / "control1_data").mkdir()
    journal = tmp_path / "control1_data" / "raft.journal"
    journal.write_bytes(b"metadata")
    with pytest.raises(prepare.SetupError, match="original"):
        prepare.prepare_env(tmp_path)
    assert journal.read_bytes() == b"metadata"
    assert not (tmp_path / ".env").exists()


def test_complete_pki_is_preserved_and_missing_leaf_pair_is_completed(tmp_path):
    certs.prepare_certificates(tmp_path, ["control1", "datanode1"], [])
    preserved = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    certs.prepare_certificates(tmp_path, ["control1", "datanode1"], [])
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == preserved
    (tmp_path / "datanode1.key").unlink()
    certs.prepare_certificates(tmp_path, ["control1", "datanode1"], [])
    assert (tmp_path / "ca.crt").read_bytes() == preserved["ca.crt"]
    assert (tmp_path / "ca.key").read_bytes() == preserved["ca.key"]
    assert (tmp_path / "control1.key").read_bytes() == preserved["control1.key"]
    assert (tmp_path / "datanode1.key").exists()
    certs.prepare_certificates(tmp_path, ["control1", "datanode1"], [])  # verifica el par recién emitido


def test_public_ca_without_key_works_only_when_requested_pairs_are_complete(tmp_path):
    certs.prepare_certificates(tmp_path, ["control1"], [])
    (tmp_path / "ca.key").unlink()
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    certs.prepare_certificates(tmp_path, ["control1"], [])
    with pytest.raises(ValueError, match="falta ca.key"):
        certs.prepare_certificates(tmp_path, ["control1", "datanode1"], [])
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


def test_missing_public_ca_does_not_rotate_existing_private_key(tmp_path):
    certs.prepare_certificates(tmp_path, ["control1"], [])
    (tmp_path / "ca.crt").unlink()
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    with pytest.raises(ValueError, match="Falta ca.crt"):
        certs.prepare_certificates(tmp_path, ["control1"], [])
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before
