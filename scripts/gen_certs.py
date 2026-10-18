#!/usr/bin/env python3
"""
Genera la PKI de DFSha: una CA propia y un certificado por componente.

Cada certificado sirve como servidor Y como cliente (mTLS entre nodos) y trae
como nombres alternativos (SAN) el nombre del componente, localhost y 127.0.0.1,
más los extra que se indiquen (IPs o DNS públicos de las VMs en AWS):

    python scripts/gen_certs.py                                  # cluster local de docker compose
    python scripts/gen_certs.py --san 54.12.34.56 --san dfsha.example.org
    python scripts/gen_certs.py --force                          # regenera todo

Salida (por defecto ./certs): ca.crt, <nombre>.crt, <nombre>.key.
Requiere:  pip install cryptography
La clave de la CA (ca.key) solo hace falta para emitir certificados: no la
copies a las VMs.
"""
import argparse
import datetime
import ipaddress
import os
from pathlib import Path
import re

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DEFAULT_NAMES = ["control1", "control2", "control3", "datanode1", "datanode2", "datanode3", "datanode4"]


def _write(path: Path, data: bytes, private: bool = False):
    mode = 0o600 if private else 0o644
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as out:
        os.chmod(path, mode)
        out.write(data)


def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DFSha"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(out: Path, days: int):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_name("DFSha CA")).issuer_name(_name("DFSha CA"))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    _write(out / "ca.key", _key_pem(key), private=True)
    _write(out / "ca.crt", cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def load_ca(out: Path):
    key = serialization.load_pem_private_key((out / "ca.key").read_bytes(), None)
    cert = x509.load_pem_x509_certificate((out / "ca.crt").read_bytes())
    if _public_bytes(key.public_key()) != _public_bytes(cert.public_key()):
        raise ValueError("ca.key no corresponde a ca.crt; restaura el par original")
    return key, cert


def _public_bytes(key) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _validate_pair(out: Path, name: str, ca_cert):
    key = serialization.load_pem_private_key((out / f"{name}.key").read_bytes(), None)
    cert = x509.load_pem_x509_certificate((out / f"{name}.crt").read_bytes())
    if _public_bytes(key.public_key()) != _public_bytes(cert.public_key()):
        raise ValueError(f"el certificado y la clave de {name} no corresponden; restaura el par original")
    try:
        cert.verify_directly_issued_by(ca_cert)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise ValueError(f"el certificado de {name} no pertenece a la CA actual") from exc
    os.chmod(out / f"{name}.key", 0o600)


def make_node_cert(out: Path, name: str, ca_key, ca_cert, sans: list[str], days: int):
    key = ec.generate_private_key(ec.SECP256R1())
    names = [x509.DNSName(name), x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    for s in sans:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(s)))
        except ValueError:
            names.append(x509.DNSName(s))
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_name(name)).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    _write(out / f"{name}.key", _key_pem(key), private=True)
    _write(out / f"{name}.crt", cert.public_bytes(serialization.Encoding.PEM))


def prepare_certificates(out: Path, names: list[str], sans: list[str], days: int = 825, force: bool = False):
    """conserva la ca y los pares completos y emite solo los que faltan, una pki a medias nunca cambia la ca sin avisar"""
    names = list(dict.fromkeys(names))
    if days <= 0:
        raise ValueError("--days debe ser positivo")
    if any(n.lower() == "ca" or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", n) for n in names):
        raise ValueError("--name debe ser un nombre de componente válido y distinto de ca")
    out.mkdir(parents=True, exist_ok=True)
    ca_crt, ca_key_path = out / "ca.crt", out / "ca.key"
    if force:
        ca_key, ca_cert = make_ca(out, days)
        pending = names
        print("CA regenerada por --force:", ca_crt)
    elif ca_crt.exists():
        ca_cert = x509.load_pem_x509_certificate(ca_crt.read_bytes())
        pending = [n for n in names if not (out / f"{n}.crt").exists() or not (out / f"{n}.key").exists()]
        if pending and not ca_key_path.exists():
            raise ValueError(
                "Existe ca.crt pero falta ca.key para completar certificados. "
                "Restaura la clave original o emite los pares faltantes desde la CA original; no se regeneró la CA."
            )
        ca_key = load_ca(out)[0] if ca_key_path.exists() else None
        if ca_key_path.exists():
            os.chmod(ca_key_path, 0o600)
        for name in names:
            if name not in pending:
                _validate_pair(out, name, ca_cert)
    else:
        if ca_key_path.exists() or any(out.glob("*.crt")) or any(out.glob("*.key")):
            raise ValueError("Falta ca.crt en una PKI existente; restaura la CA original. No se generó otra CA.")
        ca_key, ca_cert = make_ca(out, days)
        pending = names
        print("CA creada:", ca_crt)
    for name in pending:
        make_node_cert(out, name, ca_key, ca_cert, sans, days)
        print("certificado:", out / f"{name}.crt")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="certs")
    ap.add_argument("--name", action="append", help="componente (repetible); por defecto 3 ControlNodes y 4 DataNodes (el cuarto es opcional)")
    ap.add_argument("--san", action="append", default=[], help="IP o DNS extra para todos los certificados (repetible)")
    ap.add_argument("--days", type=int, default=825)
    ap.add_argument("--force", action="store_true", help="regenera aunque ya existan")
    a = ap.parse_args()

    try:
        prepare_certificates(Path(a.out), a.name or DEFAULT_NAMES, a.san, a.days, a.force)
    except (ValueError, OSError) as exc:
        ap.exit(1, f"Error de PKI: {exc}\n")


if __name__ == "__main__":
    main()
