"""shell interactivo de dfsha: directorio actual (cd/pwd), rutas relativas y autocompletado de rutas remotas como en una terminal normal (python cli.py shell), las rutas que empiezan con ! son locales: !ls, !cd"""
import cmd
import os
import posixpath
import shlex
import subprocess

from dfsha_client import DFShaClient, DFShaError


class DFShaShell(cmd.Cmd):
    intro = "DFSha — escribe 'help' para ver los comandos, 'exit' para salir."

    def __init__(self, client: DFShaClient, user: str = "", cwd: str = "/", stdin=None, stdout=None):
        super().__init__(stdin=stdin, stdout=stdout)
        self.c = client
        self.user = user
        self.cwd = cwd
        self.use_rawinput = stdin is None
        self._set_prompt()

    # utilidades

    def _set_prompt(self):
        self.prompt = f"dfsha{':' + self.user if self.user else ''} {self.cwd}> "

    def _path(self, p: str) -> str:
        if not p.startswith("/"):
            p = posixpath.join(self.cwd, p)
        return posixpath.normpath(p) if p else self.cwd

    def _say(self, text: str = ""):
        print(text, file=self.stdout)

    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except DFShaError as e:
            self._say(f"error: {e}")
        except (OSError, ValueError, IndexError) as e:
            self._say(f"error: {e if not isinstance(e, IndexError) else 'faltan argumentos (usa help)'}")
        return False

    def parseline(self, line):
        if line.startswith("!"):
            return "shell", line[1:], line
        return super().parseline(line)

    @staticmethod
    def _args(arg: str):
        return shlex.split(arg)

    @staticmethod
    def _flags(args, *flags):
        found = {f: f in args for f in flags}
        return found, [a for a in args if a not in flags]

    def emptyline(self):
        pass

    # navegación

    def do_pwd(self, arg):
        """pwd: muestra el directorio actual."""
        self._say(self.cwd)

    def do_cd(self, arg):
        """cd [dir]: cambia de directorio (sin argumento vuelve a tu home)."""
        target = self._path(arg.strip()) if arg.strip() else (f"/{self.user}" if self.user else "/")
        if self.c.kind(target) != "dir":
            raise DFShaError(f"{target}: no es un directorio")
        self.cwd = target
        self._set_prompt()

    def do_ls(self, arg):
        """ls [-l] [ruta]: lista un directorio."""
        flags, rest = self._flags(self._args(arg), "-l")
        path = self._path(rest[0]) if rest else self.cwd
        if self.c.kind(path) == "file":
            st = self.c.stat(path)
            self._say(f"{path}  {st['size']} bytes")
            return
        data = self.c.ls(path)
        for d in data["dirs"]:
            self._say(f"{d.rsplit('/', 1)[1]}/")
        for f in data["files"]:
            name = f["path"].rsplit("/", 1)[1]
            if flags["-l"]:
                self._say(f"{f['perm']:<6} {f['owner']:<12} {f['size']:>12}  {name}")
            else:
                self._say(name)

    def do_tree(self, arg):
        """tree [ruta]: muestra el árbol de directorios."""
        root = self._path(arg.strip()) if arg.strip() else self.cwd
        for dirpath, dirs, files in self.c.walk(root):
            depth = 0 if dirpath == root else dirpath[len(root):].count("/")
            indent = "  " * depth
            self._say(f"{indent}{dirpath.rsplit('/', 1)[1] or '/'}/")
            for f in files:
                self._say(f"{indent}  {f}")

    def do_stat(self, arg):
        """stat <ruta>: tamaño, versión, réplicas vivas, locks y permisos."""
        for k, v in self.c.stat(self._path(arg.strip())).items():
            self._say(f"{k}: {v}")

    # árbol de archivos

    def do_mkdir(self, arg):
        """mkdir [-p] <dir>: crea un directorio (-p crea también los intermedios)."""
        flags, rest = self._flags(self._args(arg), "-p")
        for d in rest:
            (self.c.mkdir_p if flags["-p"] else self.c.mkdir)(self._path(d))

    def do_rmdir(self, arg):
        """rmdir <dir>: borra un directorio vacío."""
        for d in self._args(arg):
            self.c.rmdir(self._path(d))

    def do_rm(self, arg):
        """rm [-r] <ruta>: borra un archivo (-r: un directorio entero)."""
        flags, rest = self._flags(self._args(arg), "-r")
        for p in rest:
            (self.c.rm_tree if flags["-r"] else self.c.rm)(self._path(p))

    def do_mv(self, arg):
        """mv <origen> <destino>: mueve o renombra (si el destino es un directorio, mueve dentro)."""
        src, dst = self._args(arg)
        src, dst = self._path(src), self._path(dst)
        if self.c.kind(dst) == "dir":
            dst = dst.rstrip("/") + "/" + src.rsplit("/", 1)[1]
        self.c.mv(src, dst)

    def do_cp(self, arg):
        """cp [-r] <origen> <destino>: copia archivos o directorios (-r)."""
        flags, rest = self._flags(self._args(arg), "-r")
        src, dst = rest
        self.c.cp(self._path(src), self._path(dst), recursive=flags["-r"])

    def do_cat(self, arg):
        """cat <archivo>: muestra el contenido."""
        for p in self._args(arg):
            with self.c.open(self._path(p), "r") as f:
                while chunk := f.read(4 * 1024 * 1024):
                    self.stdout.write(chunk.decode(errors="replace"))
        self._say()

    # transferencia entre máquina y dfsha

    def do_put(self, arg):
        """put [-r] <local> [remoto]: sube un archivo o directorio (-r); por defecto al directorio actual."""
        flags, rest = self._flags(self._args(arg), "-r")
        local = rest[0]
        remote = self._path(rest[1]) if len(rest) > 1 else self._path(os.path.basename(local.rstrip("/")))
        if self.c.kind(remote) == "dir":
            remote = remote.rstrip("/") + "/" + os.path.basename(local.rstrip("/"))
        if flags["-r"] or os.path.isdir(local):
            self._say(f"{self.c.put_tree(local, remote)} archivos subidos")
        else:
            self.c.put(local, remote)
            self._say(f"subido: {remote}")

    def do_get(self, arg):
        """get [-r] <remoto> [local]: descarga un archivo o directorio (-r)."""
        flags, rest = self._flags(self._args(arg), "-r")
        remote = self._path(rest[0])
        local = rest[1] if len(rest) > 1 else os.path.basename(remote)
        if self.c.kind(remote) == "dir":
            self._say(f"{self.c.get_tree(remote, local)} archivos descargados")
        else:
            self.c.get(remote, local)
            self._say(f"descargado: {local}")

    # compartir y bloquear

    def do_share(self, arg):
        """share <ruta> <user:NOMBRE|group:NOMBRE> <r|rw|none>: da o quita acceso."""
        path, who, perm = self._args(arg)
        self.c.share(self._path(path), who, perm)

    def do_acl(self, arg):
        """acl <ruta>: quién tiene acceso (solo el dueño)."""
        for e in self.c.acl(self._path(arg.strip())):
            self._say(f"{e['principal']}  {e['perm']}")

    def do_shared(self, arg):
        """shared: lo que otros han compartido."""
        for e in self.c.shared():
            self._say(f"[{e['type']}] {e['path']}  ({e['perm']}, dueño: {e['owner']})")

    def do_lock(self, arg):
        """lock <ruta> <shared|exclusive> [segundos]: mantiene un lock durante unos segundos."""
        import time
        args = self._args(arg)
        with self.c.open(self._path(args[0]), "r+" if args[1] == "exclusive" else "r", lock=args[1]):
            self._say(f"lock {args[1]} adquirido; se mantiene {args[2] if len(args) > 2 else 10} s")
            time.sleep(float(args[2]) if len(args) > 2 else 10)

    # comandos locales y salida

    def do_shell(self, arg):
        if arg.startswith("cd"):
            os.chdir(os.path.expanduser(arg[2:].strip() or "~"))
            return
        subprocess.run(arg, shell=True)

    def do_exit(self, arg):
        """exit: sale del shell."""
        return True

    do_quit = do_EOF = do_exit

    # autocompletado de rutas remotas

    def completedefault(self, text, line, begidx, endidx):
        base = posixpath.dirname(text)
        folder = self._path(base) if base else self.cwd
        try:
            data = self.c.ls(folder)
        except DFShaError:
            return []
        names = [d.rsplit("/", 1)[1] + "/" for d in data["dirs"]] + [f["path"].rsplit("/", 1)[1] for f in data["files"]]
        prefix = posixpath.basename(text)
        return [(base + "/" if base else "") + n for n in names if n.startswith(prefix)]


def run(client: DFShaClient, user: str = ""):
    home = f"/{user}" if user else "/"
    cwd = home if user and client.kind(home) == "dir" else "/"
    try:
        import readline  # noqa: F401  (historial y edición de línea)
    except ImportError:
        pass
    DFShaShell(client, user, cwd).cmdloop()
