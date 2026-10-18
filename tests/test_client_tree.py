"""operaciones de árbol del cliente (mv, cp, mkdir -p, put/get/rm recursivos) y shell interactivo"""
import io
import os

import pytest

from dfsha_client import DFShaError

pytestmark = pytest.mark.usefixtures("cluster_up")

KB = 1024


def make_local_tree(root, files):
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def read_all(c, path):
    with c.open(path, "r") as f:
        return f.read()


def test_mkdir_p_kind_and_walk(user):
    h = user.home
    user.mkdir_p(f"{h}/a/b/c")
    user.mkdir_p(f"{h}/a/b/c")  # idempotente
    assert user.kind(f"{h}/a/b") == "dir" and user.kind(f"{h}/nada") is None
    with user.open(f"{h}/a/b/f.txt", "w") as f:
        f.write(b"x")
    assert user.kind(f"{h}/a/b/f.txt") == "file"
    walked = {d: (sorted(ds), sorted(fs)) for d, ds, fs in user.walk(f"{h}/a")}
    assert walked == {f"{h}/a": (["b"], []), f"{h}/a/b": (["c"], ["f.txt"]), f"{h}/a/b/c": ([], [])}


def test_put_tree_get_tree_roundtrip(user, tmp_path):
    src = tmp_path / "src"
    files = {"raiz.txt": b"r", "d1/a.bin": os.urandom(300 * KB), "d1/d2/b.bin": os.urandom(5 * KB), "vacio/.keep": b""}
    make_local_tree(src, files)
    assert user.put_tree(str(src), f"{user.home}/proyecto", block_size=64 * KB) == 4
    dst = tmp_path / "dst"
    assert user.get_tree(f"{user.home}/proyecto", str(dst)) == 4
    for rel, data in files.items():
        assert (dst / rel).read_bytes() == data


def test_mv_files_and_directories(user):
    h = user.home
    user.mkdir_p(f"{h}/x/y")
    with user.open(f"{h}/x/y/f.txt", "w") as f:
        f.write(b"dato")
    user.mv(f"{h}/x/y/f.txt", f"{h}/x/g.txt")
    assert read_all(user, f"{h}/x/g.txt") == b"dato"
    user.mv(f"{h}/x", f"{h}/z")  # directorio completo
    assert read_all(user, f"{h}/z/g.txt") == b"dato" and user.kind(f"{h}/x") is None
    with pytest.raises(DFShaError, match="409"):
        user.mv(f"{h}/z", f"{h}/z/y")  # dentro de sí mismo -> 400 / destino existente -> 409
    with pytest.raises(DFShaError, match="404"):
        user.mv(f"{h}/nada", f"{h}/otro")
    with pytest.raises(DFShaError, match="404"):
        user.mv(f"{h}/z/g.txt", f"{h}/no_existe/g.txt")
    with pytest.raises(DFShaError, match="403"):
        user.mv(h, f"{h}2")  # no se mueve el home


def test_mv_keeps_permissions_and_open_sessions(make_user):
    alice, bob = make_user(), make_user()
    p = f"{alice.home}/orig.txt"
    with alice.open(p, "w") as f:
        f.write(b"contenido")
    alice.share(p, f"user:{bob.username}", "r")
    reader = bob.open(p, "r")
    alice.mv(p, f"{alice.home}/renombrado.txt")
    assert read_all(bob, f"{alice.home}/renombrado.txt") == b"contenido"  # el permiso viajó con el archivo
    assert reader.read() == b"contenido"  # y la sesión abierta sigue funcionando
    reader.close()
    with pytest.raises(DFShaError, match="403"):
        bob.mv(f"{alice.home}/renombrado.txt", f"{bob.home}/robado.txt")  # r no alcanza para mover
    alice.share(f"{alice.home}/renombrado.txt", f"user:{bob.username}", "rw")
    with pytest.raises(DFShaError, match="403"):  # rw sobre el archivo no alcanza: hay que poder
        bob.mv(f"{alice.home}/renombrado.txt", f"{alice.home}/de_bob.txt")  # escribir también en el directorio destino
    alice.mkdir(f"{alice.home}/equipo")
    alice.mv(f"{alice.home}/renombrado.txt", f"{alice.home}/equipo/doc.txt")
    alice.share(f"{alice.home}/equipo", f"user:{bob.username}", "rw")
    bob.mv(f"{alice.home}/equipo/doc.txt", f"{alice.home}/equipo/de_bob.txt")  # con rw en el directorio sí
    assert read_all(alice, f"{alice.home}/equipo/de_bob.txt") == b"contenido"


def test_cp_and_cp_recursive_and_rm_tree(user):
    h = user.home
    user.mkdir_p(f"{h}/o/sub")
    big = os.urandom(200 * KB)
    with user.open(f"{h}/o/a.bin", "w", block_size=64 * KB) as f:
        f.write(big)
    with user.open(f"{h}/o/sub/b.txt", "w") as f:
        f.write(b"bbb")
    assert user.cp(f"{h}/o/a.bin", f"{h}/copia.bin") == 1
    assert read_all(user, f"{h}/copia.bin") == big
    assert user.cp(f"{h}/o/a.bin", f"{h}/o/sub") == 1  # destino directorio: copia adentro
    assert read_all(user, f"{h}/o/sub/a.bin") == big
    with pytest.raises(DFShaError, match="directorio"):
        user.cp(f"{h}/o", f"{h}/o2")
    assert user.cp(f"{h}/o", f"{h}/o2", recursive=True) == 3
    assert read_all(user, f"{h}/o2/sub/b.txt") == b"bbb"
    # el original y la copia son independientes: borrar uno no daña al otro (los bloques no se comparten)
    user.rm_tree(f"{h}/o")
    assert user.kind(f"{h}/o") is None
    assert read_all(user, f"{h}/o2/a.bin") == big and read_all(user, f"{h}/copia.bin") == big


# shell interactivo

def run_shell(client, commands: str) -> str:
    import shell
    out = io.StringIO()
    sh = shell.DFShaShell(client, client.username, f"/{client.username}", stdin=io.StringIO(commands), stdout=out)
    sh.use_rawinput = False
    sh.prompt = ""
    sh.cmdloop(intro="")
    return out.getvalue()


def test_shell_cd_relative_paths_and_commands(user, tmp_path):
    local = tmp_path / "subir.txt"
    local.write_text("desde el shell")
    out = run_shell(user, f"""pwd
mkdir -p docs/sub
cd docs
pwd
put {local} nota.txt
ls
cat nota.txt
cp nota.txt sub/copia.txt
mv sub/copia.txt ../movido.txt
cd ..
ls
tree
stat movido.txt
cd /{user.username}/docs/inexistente
rm -r docs
ls
exit
""")
    h = user.home
    assert out.splitlines()[0] == h  # arranca en el home
    assert f"{h}/docs" in out  # pwd después de cd (rutas relativas)
    assert "nota.txt" in out and "desde el shell" in out and "movido.txt" in out
    assert "sub/" in out and "version: " in out
    assert "no es un directorio" in out  # cd a un directorio que no existe avisa y no se cae
    assert user.kind(f"{h}/docs") is None and user.kind(f"{h}/movido.txt") == "file"


def test_shell_share_and_errors_do_not_crash_it(make_user):
    alice, bob = make_user(), make_user()
    out = run_shell(alice, f"""mkdir pub
share pub user:{bob.username} r
acl pub
share pub user:fantasma r
rm no_existe
cd /
ls
exit
""")
    assert f"user:{bob.username}  r" in out
    assert "error:" in out and "404" in out  # los errores se muestran y el shell sigue
    assert alice.home.lstrip("/") in out
