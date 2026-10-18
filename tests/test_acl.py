"""compartir: permisos por usuario y grupo (acl) sobre archivos y directorios, con herencia"""
import os
import uuid

import pytest

from dfsha_client import DFShaError

pytestmark = pytest.mark.usefixtures("cluster_up")

KB = 1024


def put_bytes(client, tmp_path, remote, data, block_size=64 * KB):
    p = tmp_path / ("s_" + uuid.uuid4().hex)
    p.write_bytes(data)
    return client.put(str(p), remote, block_size=block_size)


def get_bytes(client, tmp_path, remote) -> bytes:
    p = tmp_path / ("d_" + uuid.uuid4().hex)
    client.get(remote, str(p))
    return p.read_bytes()


def read_all(client, path) -> bytes:
    with client.open(path, "r") as f:
        return f.read()


def denied(fn):
    with pytest.raises(DFShaError, match="403"):
        fn()


# archivos

def test_file_sharing_read_then_write_then_revoke(make_user, tmp_path):
    alice, bob = make_user(), make_user()
    p = f"{alice.home}/doc.bin"
    data = os.urandom(150 * KB)
    put_bytes(alice, tmp_path, p, data)
    denied(lambda: get_bytes(bob, tmp_path, p))  # sin compartir: nada

    alice.share(p, f"user:{bob.username}", "r")  # solo lectura
    assert get_bytes(bob, tmp_path, p) == data
    assert read_all(bob, p) == data
    assert bob.stat(p)["size"] == len(data)
    denied(lambda: put_bytes(bob, tmp_path, p, b"x"))  # no puede escribir...
    denied(lambda: bob.open(p, "r+"))
    denied(lambda: bob.open(p, "a"))
    denied(lambda: bob.rm(p))  # ...ni borrar
    denied(lambda: bob.acl(p))  # ni ver ni cambiar quién más tiene acceso
    denied(lambda: bob.share(p, f"user:{alice.username}", "rw"))

    alice.share(p, f"user:{bob.username}", "rw")  # sube a lectura/escritura
    with bob.open(p, "r+") as f:
        f.seek(0)
        f.write(b"EDITADO POR BOB")
    expected = b"EDITADO POR BOB" + data[len(b"EDITADO POR BOB"):]
    assert read_all(alice, p) == expected  # el dueño ve el cambio
    put_bytes(bob, tmp_path, p, b"reemplazo completo")
    assert get_bytes(alice, tmp_path, p) == b"reemplazo completo"
    assert alice.stat(p)["owner"] == alice.username  # escribir no cambia al dueño
    denied(lambda: bob.share(p, f"user:{alice.username}", "r"))  # un colaborador no puede compartir

    alice.share(p, f"user:{bob.username}", "none")  # revocar
    denied(lambda: get_bytes(bob, tmp_path, p))
    denied(lambda: bob.open(p, "r"))
    assert alice.acl(p) == []


def test_revoking_access_cuts_sessions_that_were_already_open(make_user, tmp_path):
    alice, bob = make_user(), make_user()
    p = f"{alice.home}/s.bin"
    put_bytes(alice, tmp_path, p, b"contenido" * 100)
    alice.share(p, f"user:{bob.username}", "rw")
    f = bob.open(p, "r+")
    assert f.read(9) == b"contenido"
    alice.share(p, f"user:{bob.username}", "none")
    f.write(b"X")
    denied(f.flush)  # el commit se rechaza
    denied(lambda: bob._request("POST", "/fs/resolve", json={"handle": f.handle}))
    f.close(discard=True)  # pero cerrar siempre se puede
    assert read_all(alice, p).startswith(b"contenido")


def test_acl_entries_disappear_with_the_file(make_user, tmp_path):
    alice, bob = make_user(), make_user()
    p = f"{alice.home}/temp.bin"
    put_bytes(alice, tmp_path, p, b"uno")
    alice.share(p, f"user:{bob.username}", "r")
    assert get_bytes(bob, tmp_path, p) == b"uno"
    alice.rm(p)
    put_bytes(alice, tmp_path, p, b"otro archivo, mismo nombre")
    denied(lambda: get_bytes(bob, tmp_path, p))  # no hereda el permiso del archivo anterior


# directorios: herencia y propiedad

def test_directory_share_is_inherited_and_directory_owner_keeps_control(make_user, tmp_path):
    alice, bob, carol = make_user(), make_user(), make_user()
    d = f"{alice.home}/proj"
    alice.mkdir(d)
    alice.mkdir(f"{d}/sub")
    put_bytes(alice, tmp_path, f"{d}/sub/notas.txt", b"notas de alice")
    put_bytes(alice, tmp_path, f"{alice.home}/fuera.txt", b"fuera del proyecto")

    alice.share(d, f"user:{bob.username}", "rw")
    assert bob.ls(d)["dirs"] == [f"{d}/sub"]  # ve el árbol compartido
    assert [f["path"] for f in bob.ls(f"{d}/sub")["files"]] == [f"{d}/sub/notas.txt"]
    assert get_bytes(bob, tmp_path, f"{d}/sub/notas.txt") == b"notas de alice"  # herencia a los subdirectorios
    denied(lambda: get_bytes(bob, tmp_path, f"{alice.home}/fuera.txt"))  # lo de afuera sigue prohibido
    denied(lambda: bob.ls(alice.home))

    bob.mkdir(f"{d}/de_bob")  # puede crear dentro...
    put_bytes(bob, tmp_path, f"{d}/sub/de_bob.txt", b"aporte de bob")
    assert bob.stat(f"{d}/sub/de_bob.txt")["owner"] == bob.username  # ...y es dueño de lo que crea
    assert get_bytes(alice, tmp_path, f"{d}/sub/de_bob.txt") == b"aporte de bob"  # alice, dueña del directorio, lo ve
    alice.rm(f"{d}/sub/de_bob.txt")  # y puede administrarlo
    bob.rmdir(f"{d}/de_bob")  # un colaborador rw puede borrar directorios vacíos

    denied(lambda: carol.ls(d))  # carol no tiene nada
    alice.share(d, f"user:{carol.username}", "r")
    assert get_bytes(carol, tmp_path, f"{d}/sub/notas.txt") == b"notas de alice"
    denied(lambda: put_bytes(carol, tmp_path, f"{d}/sub/c.txt", b"x"))  # r no deja crear
    denied(lambda: carol.mkdir(f"{d}/c"))
    denied(lambda: carol.rm(f"{d}/sub/notas.txt"))
    denied(lambda: carol.rmdir(f"{d}/sub"))


def test_nobody_can_modify_other_users_home_without_a_grant(make_user):
    alice, bob = make_user(), make_user()
    for call in (lambda: bob.mkdir(f"{alice.home}/x"), lambda: bob.rmdir(alice.home), lambda: bob.open(f"{alice.home}/n", "w")):
        denied(call)
    assert bob.ls("/")["dirs"] == [bob.home]


def test_ls_only_lists_what_the_user_can_see_and_reports_the_permission(make_user, tmp_path):
    alice, bob = make_user(), make_user()
    d = f"{alice.home}/mix"
    alice.mkdir(d)
    for name in ("a", "b", "c"):
        put_bytes(alice, tmp_path, f"{d}/{name}.txt", name.encode())
    alice.share(f"{d}/b.txt", f"user:{bob.username}", "r")
    alice.share(f"{d}/c.txt", f"user:{bob.username}", "rw")
    denied(lambda: bob.ls(d))  # sin permiso sobre el directorio no se lista...
    assert get_bytes(bob, tmp_path, f"{d}/b.txt") == b"b"  # ...aunque sí se llega a lo compartido por ruta
    alice.share(d, f"user:{bob.username}", "r")
    perms = {f["path"].rsplit("/", 1)[1]: f["perm"] for f in bob.ls(d)["files"]}
    assert perms == {"a.txt": "r", "b.txt": "r", "c.txt": "rw"}  # a: heredado del directorio, c: ampliado por su acl
    perms = {f["path"].rsplit("/", 1)[1]: f["perm"] for f in alice.ls(d)["files"]}
    assert set(perms.values()) == {"owner"}


def test_shared_with_me_listing(make_user, tmp_path):
    alice, bob = make_user(), make_user()
    alice.mkdir(f"{alice.home}/d")
    put_bytes(alice, tmp_path, f"{alice.home}/f.txt", b"f")
    assert bob.shared() == []
    alice.share(f"{alice.home}/d", f"user:{bob.username}", "rw")
    alice.share(f"{alice.home}/f.txt", f"user:{bob.username}", "r")
    got = {(e["path"], e["perm"], e["type"], e["owner"]) for e in bob.shared()}
    assert got == {(f"{alice.home}/d", "rw", "dir", alice.username), (f"{alice.home}/f.txt", "r", "file", alice.username)}


# grupos

def test_group_sharing_membership_and_revocation(make_user, tmp_path):
    alice, carol, dave = make_user(), make_user(), make_user()
    gname = "eq" + uuid.uuid4().hex[:8]
    d = f"{alice.home}/equipo"
    alice.mkdir(d)
    put_bytes(alice, tmp_path, f"{d}/plan.txt", b"plan del equipo")

    alice.group_create(gname)
    with pytest.raises(DFShaError, match="409"):
        alice.group_create(gname)
    alice.group_add(gname, carol.username)
    with pytest.raises(DFShaError, match="404"):
        alice.group_add(gname, "usuario_inexistente")
    with pytest.raises(DFShaError, match="403"):
        carol.group_add(gname, dave.username)  # solo el dueño administra el grupo
    assert sorted(alice.group_list()[0]["members"]) == sorted([alice.username, carol.username])
    assert [g["name"] for g in carol.group_list()] == [gname]
    assert dave.group_list() == []

    alice.share(d, f"group:{gname}", "r")
    assert get_bytes(carol, tmp_path, f"{d}/plan.txt") == b"plan del equipo"  # por estar en el grupo
    denied(lambda: get_bytes(dave, tmp_path, f"{d}/plan.txt"))
    assert [e["path"] for e in carol.shared()] == [d]

    alice.group_add(gname, dave.username)
    assert get_bytes(dave, tmp_path, f"{d}/plan.txt") == b"plan del equipo"
    alice.group_remove(gname, carol.username)
    denied(lambda: get_bytes(carol, tmp_path, f"{d}/plan.txt"))  # al salir del grupo pierde el acceso
    with pytest.raises(DFShaError, match="409"):
        alice.group_remove(gname, alice.username)  # el dueño no puede dejar su grupo

    alice.group_delete(gname)
    denied(lambda: get_bytes(dave, tmp_path, f"{d}/plan.txt"))  # borrar el grupo quita lo que se compartió con él
    assert alice.acl(d) == []


def test_acl_validation(make_user, tmp_path):
    alice, bob = make_user(), make_user()
    p = f"{alice.home}/v.txt"
    put_bytes(alice, tmp_path, p, b"v")
    with pytest.raises(DFShaError, match="404"):
        alice.share(f"{alice.home}/no_existe", f"user:{bob.username}", "r")
    with pytest.raises(DFShaError, match="404"):
        alice.share(p, "user:fantasma_que_no_existe", "r")
    with pytest.raises(DFShaError, match="404"):
        alice.share(p, "group:grupo_que_no_existe", "r")
    with pytest.raises(DFShaError, match="422"):
        alice.share(p, f"user:{bob.username}", "admin")
    with pytest.raises(DFShaError, match="422"):
        alice.share(p, f"{bob.username}", "r")  # falta el prefijo user:/group:
    with pytest.raises(DFShaError, match="404"):
        alice.share("/", f"user:{bob.username}", "r")  # la raíz no se comparte
    alice.share(p, f"user:{bob.username}", "r")
    assert alice.acl(p) == [{"principal": f"user:{bob.username}", "perm": "r"}]
    assert alice.stat(p)["acl"] == [{"principal": f"user:{bob.username}", "perm": "r"}]
    assert bob.stat(p)["acl"] is None  # solo el dueño ve la lista de permisos


def test_locks_and_versions_work_across_users(make_user, tmp_path):
    alice, bob = make_user(), make_user()
    p = f"{alice.home}/shared_lock.txt"
    put_bytes(alice, tmp_path, p, b"x")
    alice.share(p, f"user:{bob.username}", "rw")
    a = alice.open(p, "r+", lock="exclusive")
    with pytest.raises(DFShaError, match="423"):
        bob.open(p, "r+", lock="exclusive", lock_timeout=0)  # el lock de alice protege frente a bob
    denied_put = pytest.raises(DFShaError, match="423")
    with denied_put:
        put_bytes(bob, tmp_path, p, b"y")
    a.close()
    with bob.open(p, "r+", lock="exclusive") as f:
        f.write(b"B")
    assert read_all(alice, p) == b"B"
