"""
CLI de DFSha (capa fina sobre dfsha_client.DFShaClient).

Uso:
    python cli.py register <user> <pass>
    python cli.py login <user> <pass>
    python cli.py put <archivo_local> <path_remoto>
    python cli.py get <path_remoto> <archivo_local>
    python cli.py ls [path]
    python cli.py rmdir <path>

Árbol de archivos (con -r se opera sobre directorios enteros):
    python cli.py shell                                  (consola con cd, rutas relativas y autocompletado)
    python cli.py mkdir [-p] <path>
    python cli.py mv <origen> <destino>
    python cli.py cp [-r] <origen> <destino>
    python cli.py tree [path]
    python cli.py put [-r] <local> <remoto>      get [-r] <remoto> <local>      rm [-r] <path>

Cuenta y seguridad:
    python cli.py login <user> <pass> [codigo_2fa]     (o define DFSHA_OTP)
    python cli.py apikey-login <clave>                  (sustituye a contraseña + 2FA)
    python cli.py passwd <clave_actual> <clave_nueva>
    python cli.py logout-all                            (revoca todas tus sesiones)
    python cli.py 2fa setup | enable <codigo> | disable <pass> [codigo]
    python cli.py apikey create [etiqueta] | list | revoke <key_id>

Operación (solo el usuario admin):
    python cli.py status                                (nodos, réplicas, líder Raft)

Compartir (permisos por usuario o grupo, heredados por el árbol):
    python cli.py share <path> <user:NOMBRE|group:NOMBRE> <r|rw|none>
    python cli.py acl <path>                            (quién tiene acceso; solo el dueño)
    python cli.py shared                                (lo que otros compartieron conmigo)
    python cli.py group create <nombre> | ls | add <nombre> <user> | remove <nombre> <user> | delete <nombre>

Acceso tipo archivo (RF3: open/read/write/close/lock):
    python cli.py stat <path>
    python cli.py cat <path>
    python cli.py read <path> <offset> <largo>       (bytes a stdout)
    python cli.py write <path> <offset> <texto|->    (escribe en el offset; '-' = stdin; crea si no existe)
    python cli.py append <path> <texto|->
    python cli.py truncate <path> <tamaño>
    python cli.py lock <path> <shared|exclusive> [segundos]   (mantiene el lock ese tiempo)

Variables: CONTROL_NODE_URL (uno o varios ControlNodes separados por coma; por defecto los 3 locales),
           DFSHA_CA_CERT (CA del cluster para verificar TLS; por defecto certs/ca.crt),
           DFSHA_BLOCK_SIZE (bytes; opcional, el servidor lo acota).
"""
import os
import sys
import time
import json

from dfsha_client import DFShaClient, DFShaError, DEFAULT_URLS

CONTROL_NODE_URL = os.environ.get("CONTROL_NODE_URL", DEFAULT_URLS)
TOKEN_FILE = os.path.expanduser("~/.dfsha_token")


def _client(need_session: bool = True) -> DFShaClient:
    token = None
    if need_session:
        if not os.path.exists(TOKEN_FILE):
            raise DFShaError("No hay sesión. Corre: python cli.py login <user> <pass>")
        with open(TOKEN_FILE) as f:
            token = f.read().strip()
    return DFShaClient(CONTROL_NODE_URL, token)


def _save_token(token: str):
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token)


def run(cmd: str, args: list[str]):
    if cmd == "register":
        _client(False).register(args[0], args[1])
        print("Usuario creado. Ahora puedes hacer login.")
    elif cmd == "login":
        otp = args[2] if len(args) > 2 else os.environ.get("DFSHA_OTP")
        _save_token(_client(False).login(args[0], args[1], otp))
        print("Login OK")
    elif cmd == "apikey-login":
        _save_token(_client(False).login_apikey(args[0]))
        print("Login OK (API key)")
    elif cmd == "passwd":
        _save_token(_client().change_password(args[0], args[1]))
        print("Contraseña cambiada; las demás sesiones quedaron revocadas")
    elif cmd == "logout-all":
        _client().logout_all()
        os.path.exists(TOKEN_FILE) and os.remove(TOKEN_FILE)
        print("Todas las sesiones revocadas")
    elif cmd == "2fa":
        c = _client()
        if args[0] == "setup":
            r = c.totp_setup()
            print(f"Secreto: {r['secret']}\nURI (escanéala o pégala en tu app de autenticación): {r['uri']}\n"
                  "Confirma con: python cli.py 2fa enable <codigo>")
        elif args[0] == "enable":
            c.totp_enable(args[1]); print("2FA activado")
        elif args[0] == "disable":
            c.totp_disable(args[1], args[2] if len(args) > 2 else None); print("2FA desactivado")
        else:
            raise IndexError
    elif cmd == "apikey":
        c = _client()
        if args[0] == "create":
            r = c.apikey_create(args[1] if len(args) > 1 else "")
            print(f"key_id: {r['key_id']}\nclave: {r['key']}\n(guárdala: no se vuelve a mostrar)")
        elif args[0] == "list":
            for k in c.apikey_list():
                print(f"{k['key_id']}  {k['label'] or '-'}")
        elif args[0] == "revoke":
            c.apikey_revoke(args[1]); print("OK")
        else:
            raise IndexError
    elif cmd == "status":
        st = _client().cluster_status()
        r = st["raft"]
        print(f"ControlNode líder: {r['leader']} (término {r['term']}, nodo consultado: {r['self']})")
        print(f"archivos: {st['files']}  bloques: {st['blocks']}  "
              f"sub-replicados: {st['under_replicated_blocks']}  perdidos: {st['lost_blocks']}  "
              f"factor de replicación: {st['replication_factor']}")
        for n in st["datanodes"]:
            print(f"  {n['node_id']:<10} {'VIVO ' if n['alive'] else 'CAÍDO'}  {n['blocks']:>5} bloques  "
                  f"{n['used_bytes'] / 1e6:>9.1f} MB  (visto hace {n['seen_ago']} s)")
        print(f"seguridad: TLS={'sí' if st['security']['tls'] else 'NO'}"
              f"{'  (¡secreto de desarrollo!)' if st['security']['dev_secret'] else ''}")
    elif cmd == "share":
        _client().share(args[0], args[1], args[2]); print("OK")
    elif cmd == "acl":
        for e in _client().acl(args[0]):
            print(f"{e['principal']}  {e['perm']}")
    elif cmd == "shared":
        for e in _client().shared():
            print(f"[{e['type']}] {e['path']}  ({e['perm']}, dueño: {e['owner']}, vía {e['principal']})")
    elif cmd == "group":
        c = _client()
        if args[0] == "create":
            c.group_create(args[1]); print("OK")
        elif args[0] == "ls":
            for g in c.group_list():
                print(f"{g['name']}  dueño: {g['owner']}  miembros: {', '.join(g['members'])}")
        elif args[0] == "add":
            c.group_add(args[1], args[2]); print("OK")
        elif args[0] == "remove":
            c.group_remove(args[1], args[2]); print("OK")
        elif args[0] == "delete":
            c.group_delete(args[1]); print("OK")
        else:
            raise IndexError
    elif cmd == "shell":
        import shell
        c = _client()
        shell.run(c, c.username)
    elif cmd == "mkdir":
        flags = [a for a in args if a == "-p"]
        rest = [a for a in args if a != "-p"]
        (_client().mkdir_p if flags else _client().mkdir)(rest[0]); print("OK")
    elif cmd == "mv":
        _client().mv(args[0], args[1]); print("OK")
    elif cmd == "cp":
        recursive = "-r" in args
        rest = [a for a in args if a != "-r"]
        print(f"OK ({_client().cp(rest[0], rest[1], recursive=recursive)} archivos)")
    elif cmd == "tree":
        c = _client()
        root = args[0] if args else "/"
        for dirpath, dirs, files in c.walk(root):
            depth = 0 if dirpath == root else dirpath[len(root.rstrip("/")):].count("/")
            print("  " * depth + (dirpath.rsplit("/", 1)[1] or "/") + "/")
            for f in files:
                print("  " * depth + "  " + f)
    elif cmd == "rmdir":
        _client().rmdir(args[0]); print("OK")
    elif cmd == "rm":
        rest = [a for a in args if a != "-r"]
        (_client().rm_tree if "-r" in args else _client().rm)(rest[0]); print("OK")
    elif cmd == "ls":
        data = _client().ls(args[0] if args else "/")
        for d in data["dirs"]:
            print(f"[dir]  {d}")
        for f in data["files"]:
            who = "" if f.get("perm") == "owner" else f"  [{f.get('perm')}, dueño: {f.get('owner')}]"
            print(f"[file] {f['path']}  ({f['size']} bytes){who}")
    elif cmd == "put" and ("-r" in args or (len(args) > 0 and os.path.isdir(args[0]))):
        rest = [a for a in args if a != "-r"]
        bs = int(os.environ["DFSHA_BLOCK_SIZE"]) if "DFSHA_BLOCK_SIZE" in os.environ else None
        print(f"{_client().put_tree(rest[0], rest[1], block_size=bs)} archivos subidos a {rest[1]}")
    elif cmd == "get" and ("-r" in args or _client().kind(args[0]) == "dir"):
        rest = [a for a in args if a != "-r"]
        print(f"{_client().get_tree(rest[0], rest[1])} archivos descargados a {rest[1]}")
    elif cmd == "put":
        bs = int(os.environ["DFSHA_BLOCK_SIZE"]) if "DFSHA_BLOCK_SIZE" in os.environ else None
        res = _client().put(
            args[0], args[1], block_size=bs,
            progress=lambda i, n, ok, tot: print(f"bloque {i + 1}/{n}: escrito en {ok}/{tot} réplicas"),
        )
        extra = f" ({res['under_replicated_blocks']} bloques con réplicas pendientes)" if res.get("under_replicated_blocks") else ""
        print(f"Subido: {args[1]}{extra}")
    elif cmd == "get":
        _client().get(args[0], args[1])
        print(f"Descargado: {args[1]}")
    elif cmd == "stat":
        print(json.dumps(_client().stat(args[0]), indent=2, ensure_ascii=False))
    elif cmd == "cat":
        with _client().open(args[0], "r") as f:
            while chunk := f.read(4 * 1024 * 1024):
                sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
    elif cmd == "read":
        with _client().open(args[0], "r") as f:
            f.seek(int(args[1]))
            sys.stdout.buffer.write(f.read(int(args[2])))
            sys.stdout.buffer.flush()
    elif cmd in ("write", "append"):
        text = args[-1]
        data = sys.stdin.buffer.read() if text == "-" else text.encode()
        client = _client()
        if cmd == "append":
            with client.open(args[0], "a") as f:
                f.write(data)
        else:
            try:
                f = client.open(args[0], "r+")
            except DFShaError as e:
                if e.status != 404:
                    raise
                f = client.open(args[0], "w+")
            with f:
                f.seek(int(args[1]))
                f.write(data)
        print(f"OK ({len(data)} bytes)")
    elif cmd == "truncate":
        with _client().open(args[0], "r+") as f:
            f.truncate(int(args[1]))
        print("OK")
    elif cmd == "lock":
        hold = float(args[2]) if len(args) > 2 else 30.0
        with _client().open(args[0], "r+" if args[1] == "exclusive" else "r", lock=args[1]) as f:
            print(f"Lock {args[1]} adquirido sobre {args[0]}; se mantiene {hold:g} s (Ctrl+C para soltarlo)")
            try:
                time.sleep(hold)
            except KeyboardInterrupt:
                pass
        print("Lock liberado")
    else:
        print(__doc__)
        sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    try:
        run(sys.argv[1], sys.argv[2:])
    except IndexError:
        print(__doc__)
        sys.exit(1)
    except (DFShaError, OSError) as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
