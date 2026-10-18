"""seguridad: tls/mtls, tokens de acceso a bloques, autenticación de nodos, cifrado en reposo, sesiones, api keys, 2fa y bloqueo por intentos fallidos"""
import base64
import hashlib
import hmac
import struct
import time
import uuid

import grpc
import pytest
import requests

import dfsha_pb2
import dfsha_pb2_grpc
import dfsha_security as sec
from conftest import CA, KEYS, NODES, URL, block_token, compose, datanode_channel, node_blocks
from dfsha_client import DFShaClient, DFShaError

pytestmark = pytest.mark.usefixtures("cluster_up")

KB = 1024


def put_bytes(client, tmp_path, remote, data, block_size=64 * KB):
    p = tmp_path / ("s_" + uuid.uuid4().hex)
    p.write_bytes(data)
    client.put(str(p), remote, block_size=block_size)


def first_block(client, path) -> dict:
    return client._request("GET", f"/files{path}")["blocks"][0]


def holder_port(block) -> int:
    return 6000 + int(block["replicas"][0][-1])


def code_of(fn) -> str:
    """código grpc del error que lanza fn (o 'OK')"""
    try:
        fn()
        return "OK"
    except grpc.RpcError as e:
        return e.code().name


def stub(port, ca=True):
    return dfsha_pb2_grpc.DataNodeStub(datanode_channel(port, ca))


def _code(secret: str, counter: int) -> str:
    digest = hmac.new(base64.b32decode(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** 6:06d}"


def totp(secret: str, used: set) -> str:
    """código totp (rfc 6238: hmac-sha1, 30 s, 6 dígitos) de una ventana aceptada (±1) que todavía no se haya usado, porque el servidor no deja reutilizar un código"""
    now = int(time.time() // 30)
    for counter in (now, now + 1, now - 1):
        if counter not in used:
            used.add(counter)
            return _code(secret, counter)
    raise AssertionError("no quedan ventanas TOTP sin usar")


# transporte: tls en rest y grpc, mtls entre nodos

def test_rest_api_is_https_with_a_verifiable_certificate():
    assert requests.get("https://localhost:8001/health", verify=CA, timeout=5).ok
    with pytest.raises(requests.exceptions.SSLError):  # sin confiar en la ca del cluster
        requests.get("https://localhost:8001/health", timeout=5)
    try:  # y el puerto no habla http en claro
        r = requests.get("http://localhost:8001/health", timeout=5)
        assert not r.ok
    except requests.exceptions.RequestException:
        pass


def test_client_refuses_a_cluster_whose_certificate_it_cannot_verify(tmp_path):
    import sys
    from conftest import ROOT
    sys.path.insert(0, str(ROOT / "scripts"))
    import gen_certs
    gen_certs.make_ca(tmp_path, 1)  # una ca válida, pero que no es la del cluster
    with pytest.raises(DFShaError, match="TLS"):
        DFShaClient(URL, ca_cert=str(tmp_path / "ca.crt")).login("x", "y123456")


def test_datanode_public_port_is_tls_only(user, tmp_path):
    put_bytes(user, tmp_path, f"{user.home}/t.bin", b"x" * 100)
    b = first_block(user, f"{user.home}/t.bin")
    port = holder_port(b)
    req = dfsha_pb2.BlockId(block_id=b["block_id"])
    meta = (("x-dfsha-token", b["token"]),)
    assert code_of(lambda: stub(port).ReadBlock(req, metadata=meta, timeout=5)) == "OK"
    assert code_of(lambda: stub(port, ca=False).ReadBlock(req, metadata=meta, timeout=5)) == "UNAVAILABLE"


def test_internal_port_is_not_published_and_requires_a_client_certificate(user, tmp_path):
    from test_integration import internal_call
    with pytest.raises(OSError):
        import socket
        socket.create_connection(("localhost", 6100), timeout=2)  # no se publica al host
    p = f"{user.home}/m.bin"
    put_bytes(user, tmp_path, p, b"x" * 100)
    b = first_block(user, p)
    node = f"datanode{b['replicas'][0][-1]}"
    ghost = uuid.uuid4().hex
    assert internal_call(node, ghost, "d", node, with_cert=True) == "OK"  # mtls + token: permitido
    assert internal_call(node, ghost, "d", node, with_cert=False) == "UNAVAILABLE"  # sin certificado de cliente
    assert internal_call(node, ghost, "r", node, with_cert=True) == "PERMISSION_DENIED"  # token de otra operación


# tokens de acceso a bloques

def test_block_access_needs_a_valid_token_for_that_block_and_operation(make_user, tmp_path):
    alice = make_user()
    secret = b"contenido-privado-" * 10
    put_bytes(alice, tmp_path, f"{alice.home}/s.bin", secret)
    b = first_block(alice, f"{alice.home}/s.bin")
    port, bid = holder_port(b), b["block_id"]
    other_bid = uuid.uuid4().hex
    read = lambda tok: stub(port).ReadBlock(dfsha_pb2.BlockId(block_id=bid), timeout=5,
                                            metadata=(("x-dfsha-token", tok),) if tok is not None else None)
    assert code_of(lambda: read(None)) == "PERMISSION_DENIED"  # sin token
    assert code_of(lambda: read("basura.sin.firma")) == "PERMISSION_DENIED"  # token mal formado
    assert code_of(lambda: read(block_token(other_bid, "r"))) == "PERMISSION_DENIED"  # token de otro bloque
    assert code_of(lambda: read(block_token(bid, "w"))) == "PERMISSION_DENIED"  # token de otra operación
    assert code_of(lambda: read(block_token(bid, "r", ttl=-1))) == "PERMISSION_DENIED"  # vencido
    forged = sec.make_block_token(sec.Keys("otro-secreto"), bid, "r")
    assert code_of(lambda: read(forged)) == "PERMISSION_DENIED"  # firmado con otra clave
    assert read(b["token"]).data == secret  # el del control node sí sirve


def test_write_token_cannot_be_used_to_read_and_vice_versa(user, tmp_path):
    put_bytes(user, tmp_path, f"{user.home}/w.bin", b"x" * 50)
    b = first_block(user, f"{user.home}/w.bin")
    port, fresh = holder_port(b), uuid.uuid4().hex
    write = lambda tok: stub(port).WriteBlock(dfsha_pb2.Block(block_id=fresh, data=b"zz"), timeout=5,
                                              metadata=(("x-dfsha-token", tok),))
    assert code_of(lambda: write(block_token(fresh, "r"))) == "PERMISSION_DENIED"
    assert code_of(lambda: write(block_token(uuid.uuid4().hex, "w"))) == "PERMISSION_DENIED"
    assert write(block_token(fresh, "w")).success
    compose("exec", "-T", f"datanode{port - 6000}", "rm", "-f", f"/data/{fresh}.blk")


def test_public_port_never_exposes_internal_operations(user, tmp_path):
    p = f"{user.home}/i.bin"
    put_bytes(user, tmp_path, p, b"x" * 100)
    b = first_block(user, p)
    port, bid = holder_port(b), b["block_id"]
    holder = f"datanode{port - 6000}"
    d = lambda: stub(port).DeleteBlock(dfsha_pb2.BlockId(block_id=bid), timeout=5,
                                       metadata=(("x-dfsha-token", block_token(bid, "d")),))
    x = lambda: stub(port).ReplicateBlock(dfsha_pb2.ReplicateRequest(block_id=bid, source_address="x:1"), timeout=5,
                                          metadata=(("x-dfsha-token", block_token(bid, "x")),))
    assert code_of(d) == "PERMISSION_DENIED"  # aunque el token sea válido, ese puerto no borra
    assert code_of(x) == "PERMISSION_DENIED"
    assert bid in node_blocks(holder)


def test_controlnode_only_hands_out_tokens_for_what_the_user_may_access(make_user, tmp_path):
    alice, bob = make_user(), make_user()
    p = f"{alice.home}/priv.bin"
    put_bytes(alice, tmp_path, p, b"x" * 100)
    with pytest.raises(DFShaError, match="403"):
        bob._request("GET", f"/files{p}")  # sin permiso no hay bloques ni tokens
    with pytest.raises(DFShaError, match="403"):
        bob.open(p, "r")


# autenticación de los datanodes

def test_datanode_registration_is_authenticated_and_validated():
    body = {"node_id": "datanode1", "address": "localhost:6001", "internal_address": "datanode1:6100"}
    url = "https://localhost:8001/datanodes/register"
    kw = dict(json=body, verify=CA, timeout=5)
    assert requests.post(url, **kw).status_code == 401  # sin token
    forged = {"X-DFSha-Node-Token": sec.make_node_token(sec.Keys("otro-secreto"), "datanode1")}
    assert requests.post(url, headers=forged, **kw).status_code == 401  # firmado con otra clave
    other = {"X-DFSha-Node-Token": sec.make_node_token(KEYS, "datanode2")}
    assert requests.post(url, headers=other, **kw).status_code == 401  # token de otro nodo
    ok = {"X-DFSha-Node-Token": sec.make_node_token(KEYS, "datanode1")}
    bad = {**body, "address": "http://evil.example.com:1/../x"}
    assert requests.post(url, headers=ok, **{**kw, "json": bad}).status_code == 400  # dirección inventada
    assert requests.post(url, headers=ok, **{**kw, "json": {**body, "node_id": "../etc"}}).status_code == 401
    assert requests.get("https://localhost:8001/datanodes", verify=CA, timeout=5).status_code == 401  # la topología es solo para usuarios
    user = DFShaClient(URL)
    user.register(name := "u" + uuid.uuid4().hex[:10], "secret123")
    user.login(name, "secret123")
    nodes = user._request("GET", "/datanodes")
    assert set(nodes) <= set(NODES) | {"datanode4"}  # nadie se coló


# cifrado en reposo

def raw_block(node: str, block_id: str) -> bytes:
    out = compose("exec", "-T", node, "python", "-c",
                  f"import sys,base64; sys.stdout.write(base64.b64encode(open('/data/{block_id}.blk','rb').read()).decode())")
    return base64.b64decode(out)


def test_blocks_are_encrypted_at_rest(user, tmp_path):
    marker = b"DATO-MUY-SECRETO-" * 200
    p = f"{user.home}/enc.bin"
    put_bytes(user, tmp_path, p, marker, block_size=64 * KB)
    meta = user._request("GET", f"/files{p}")
    checked = 0
    for b in meta["blocks"]:
        for addr in b["replicas"]:
            raw = raw_block(f"datanode{addr[-1]}", b["block_id"])
            assert raw[:4] == b"DFS2" and b"DATO-MUY-SECRETO" not in raw
            assert len(raw) >= b["size"]  # cifrado de verdad, no cortado
            checked += 1
    assert checked >= 2
    dst = tmp_path / "back.bin"
    user.get(p, str(dst))
    assert dst.read_bytes() == marker  # y se descifra bien al leer


def test_an_encrypted_block_cannot_be_passed_off_under_another_id(user, tmp_path):
    """el id del bloque va como dato autenticado: copiar el archivo de un bloque con otro nombre falla al descifrar"""
    pa, pb = f"{user.home}/a.bin", f"{user.home}/b.bin"
    put_bytes(user, tmp_path, pa, b"A" * 1000)
    put_bytes(user, tmp_path, pb, b"B" * 1000)
    ba, bb = first_block(user, pa), first_block(user, pb)
    shared = {a[-1] for a in ba["replicas"]} & {a[-1] for a in bb["replicas"]}
    if not shared:
        pytest.skip("los dos bloques cayeron en nodos distintos; reintenta")
    node = f"datanode{sorted(shared)[0]}"
    compose("exec", "-T", node, "cp", f"/data/{ba['block_id']}.blk", f"/data/{bb['block_id']}.blk")
    port = 6000 + int(node[-1])
    read_b = lambda: stub(port).ReadBlock(dfsha_pb2.BlockId(block_id=bb["block_id"]), timeout=5,
                                          metadata=(("x-dfsha-token", block_token(bb["block_id"], "r")),))
    assert code_of(read_b) == "DATA_LOSS"
    dst = tmp_path / "b.out"
    user.get(pb, str(dst))  # el cliente pasa a la réplica sana
    assert dst.read_bytes() == b"B" * 1000


# sesiones

def test_forged_expired_and_garbage_session_tokens_are_rejected(make_user):
    user = make_user()
    good = user.token
    for bad in (good[:-3] + "abc", "", "x.y", "Bearer", good.split(".")[0] + ".00" * 20):
        with pytest.raises(DFShaError, match="401"):
            DFShaClient(URL, bad).ls("/")
    expired = sec.make_session_token(KEYS, user.username, 0, ttl=-5)
    with pytest.raises(DFShaError, match="401"):
        DFShaClient(URL, expired).ls("/")
    forged = sec.make_session_token(sec.Keys("otro-secreto"), user.username, 0, ttl=3600)
    with pytest.raises(DFShaError, match="401"):
        DFShaClient(URL, forged).ls("/")
    assert user.ls("/")["dirs"] == [user.home]


def test_logout_all_revokes_every_session(make_user):
    user = make_user()
    second = DFShaClient(URL)
    second.login(user.username, "secret123")
    user.logout_all()
    for c in (user, second):
        with pytest.raises(DFShaError, match="401"):
            c.ls("/")
    assert DFShaClient(URL).login(user.username, "secret123")  # y se puede volver a entrar


def test_password_change_revokes_other_sessions(make_user):
    user = make_user()
    other = DFShaClient(URL)
    other.login(user.username, "secret123")
    with pytest.raises(DFShaError, match="401"):
        user.change_password("incorrecta", "nuevaclave1")
    user.change_password("secret123", "nuevaclave1")
    assert user.ls("/")["dirs"] == [user.home]  # la sesión que cambió la clave sigue
    with pytest.raises(DFShaError, match="401"):
        other.ls("/")  # las demás quedaron revocadas
    with pytest.raises(DFShaError, match="401"):
        DFShaClient(URL).login(user.username, "secret123")
    assert DFShaClient(URL).login(user.username, "nuevaclave1")


def test_registration_validation(make_user):
    c = DFShaClient(URL)
    for name, pw in (("ab", "secret123"), ("con espacio", "secret123"), ("../root", "secret123"), ("okname", "123")):
        with pytest.raises(DFShaError, match="422"):
            c.register(name, pw)
    u = make_user()
    with pytest.raises(DFShaError, match="409"):
        c.register(u.username, "secret123")


def test_repeated_failed_logins_lock_the_account_temporarily(make_user):
    user, bystander = make_user(), make_user()
    c = DFShaClient(URL)
    for _ in range(5):
        with pytest.raises(DFShaError, match="401"):
            c.login(user.username, "mala-clave")
    with pytest.raises(DFShaError, match="429"):
        c.login(user.username, "secret123")  # ni siquiera la correcta durante el bloqueo
    assert DFShaClient(URL).login(bystander.username, "secret123")  # las otras cuentas no se ven afectadas


# api keys

def test_api_keys(make_user):
    user, stranger = make_user(), make_user()
    k = user.apikey_create("ci")
    assert k["key"].startswith("dfk_") and k["key_id"] in k["key"]
    listed = user.apikey_list()
    assert [x["key_id"] for x in listed] == [k["key_id"]] and "key" not in listed[0] and listed[0]["label"] == "ci"
    c = DFShaClient(URL)
    c.login_apikey(k["key"])
    assert c.ls("/")["dirs"] == [user.home]  # actúa como el dueño de la clave
    with pytest.raises(DFShaError, match="404"):
        stranger.apikey_revoke(k["key_id"])  # nadie más puede revocarla
    with pytest.raises(DFShaError, match="401"):
        DFShaClient(URL).login_apikey(k["key"][:-1] + ("0" if k["key"][-1] != "0" else "1"))  # secreto equivocado
    with pytest.raises(DFShaError, match="401"):
        DFShaClient(URL).login_apikey("no-es-una-clave")
    user.apikey_revoke(k["key_id"])
    with pytest.raises(DFShaError, match="401"):
        DFShaClient(URL).login_apikey(k["key"])
    assert user.apikey_list() == []


# 2fa (totp)

def test_two_factor_authentication(make_user):
    user = make_user()
    used: set = set()
    setup = user.totp_setup()
    secret = setup["secret"]
    assert setup["uri"].startswith("otpauth://totp/DFSha:") and secret in setup["uri"]
    assert DFShaClient(URL).login(user.username, "secret123")  # pendiente de confirmar: todavía no se exige
    with pytest.raises(DFShaError, match="401"):
        user.totp_enable("000000")
    first = totp(secret, used)
    user.totp_enable(first)

    c = DFShaClient(URL)
    with pytest.raises(DFShaError, match="401.*2FA"):
        c.login(user.username, "secret123")  # falta el segundo factor
    with pytest.raises(DFShaError, match="401"):
        c.login(user.username, "secret123", otp="123456")
    with pytest.raises(DFShaError, match="401"):
        c.login(user.username, "secret123", otp=first)  # el código de la activación ya se usó
    code = totp(secret, used)
    c.login(user.username, "secret123", otp=code)
    with pytest.raises(DFShaError, match="401"):
        DFShaClient(URL).login(user.username, "secret123", otp=code)  # un código no se puede reutilizar
    k = user.apikey_create("sin-2fa")
    DFShaClient(URL).login_apikey(k["key"])  # las api keys no piden 2fa

    with pytest.raises(DFShaError, match="401"):
        user.totp_disable("secret123", code="000000")
    user.totp_disable("secret123", code=totp(secret, used))
    assert DFShaClient(URL).login(user.username, "secret123")  # vuelve a bastar la contraseña
