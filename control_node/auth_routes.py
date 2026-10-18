"""endpoints de autenticación (/auth), grupos (/groups) y permisos (/acl)"""
import re
import time
import hmac
import uuid
import secrets
import hashlib
from typing import Optional

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field

import config
import storage
import access
from cluster import cluster

router = APIRouter()

_USER_RE = r"^[A-Za-z0-9_.-]{3,32}$"
_GROUP_RE = r"^[A-Za-z0-9_.-]{2,32}$"


def _user(authorization: Optional[str]) -> str:
    return access.current_user(authorization)


# registro, login y sesiones

class UserRegisterRequest(BaseModel):
    username: str = Field(pattern=_USER_RE)
    password: str = Field(min_length=6, max_length=128)


class LoginRequest(BaseModel):
    username: str
    password: str
    otp: Optional[str] = None  # código de 6 dígitos si el usuario tiene 2fa


@router.post("/auth/register")
def register(req: UserRegisterRequest, authorization: str = Header(None)):
    if req.username.lower() in config.RESERVED_USERS:
        raise HTTPException(409, "ese nombre de usuario está reservado")
    if not config.ALLOW_REGISTRATION and access.current_user(authorization) != "admin":
        raise HTTPException(403, "el registro público está cerrado: solo el usuario admin puede crear cuentas")
    res = cluster.write("register_user", username=req.username, password_hash=access.hash_password(req.password))
    if res == "name_taken":
        raise HTTPException(409, "ese nombre de usuario no está disponible")
    if res == "exists":
        raise HTTPException(409, "el usuario ya existe")
    return {"ok": True, "home": "/" + req.username}  # home propio, como /user/<name> en hdfs


@router.post("/auth/login")
def login(req: LoginRequest):
    access.check_login_allowed(req.username)
    user = storage.get_user(req.username)
    if not access.verify_password(req.password, user["password_hash"] if user else None):
        access.record_login_failure(req.username)
        raise HTTPException(401, "credenciales inválidas")
    if user["totp_enabled"]:
        if not req.otp:
            raise HTTPException(401, "se requiere el código 2FA (campo otp)")
        if not access.verify_totp(req.username, user["totp_secret"], req.otp):
            access.record_login_failure(req.username)
            raise HTTPException(401, "código 2FA inválido")
    access.clear_login_failures(req.username)
    return {"token": access.make_token(req.username)}


class ApiKeyLoginRequest(BaseModel):
    key: str


@router.post("/auth/apikey-login")
def apikey_login(req: ApiKeyLoginRequest):
    """cambia una api key por un token de sesión (las api keys reemplazan contraseña + 2fa)"""
    m = re.fullmatch(r"dfk_([0-9a-f]{12})_([0-9a-f]{32})", req.key)
    access.check_login_allowed("apikey:" + (m.group(1) if m else "?"))
    rec = storage.get_apikey(m.group(1)) if m else None
    ok = bool(rec) and hmac.compare_digest(rec["secret_hash"], hashlib.sha256(m.group(2).encode()).hexdigest())
    if not ok:
        access.record_login_failure("apikey:" + (m.group(1) if m else "?"))
        raise HTTPException(401, "API key inválida o revocada")
    return {"token": access.make_token(rec["owner"]), "user": rec["owner"]}


@router.post("/auth/logout-all")
def logout_all(authorization: str = Header(None)):
    """revoca todas las sesiones del usuario (incluida la actual)"""
    user = _user(authorization)
    cluster.write("bump_epoch", username=user)
    return {"ok": True}


class PasswordChange(BaseModel):
    old_password: str
    new_password: str = Field(min_length=6, max_length=128)


@router.post("/auth/password")
def change_password(req: PasswordChange, authorization: str = Header(None)):
    user = _user(authorization)
    u = storage.get_user(user)
    if not access.verify_password(req.old_password, u["password_hash"]):
        raise HTTPException(401, "la contraseña actual no es correcta")
    cluster.write("set_password", username=user, password_hash=access.hash_password(req.new_password))
    return {"token": access.make_token(user)}  # las demás sesiones quedan revocadas


# 2fa (totp)

@router.post("/auth/2fa/setup")
def totp_setup(authorization: str = Header(None)):
    user = _user(authorization)
    secret = access.new_totp_secret()
    try:
        cluster.write("totp_setup", username=user, secret=secret)
    except storage.Conflict:
        raise HTTPException(409, "2FA ya está activo: desactívalo primero con contraseña y código 2FA")
    return {"secret": secret, "uri": access.totp_uri(user, secret),
            "next": "confirma con POST /auth/2fa/enable {code} usando tu app de autenticación"}


class CodeRequest(BaseModel):
    code: str


@router.post("/auth/2fa/enable")
def totp_enable(req: CodeRequest, authorization: str = Header(None)):
    user = _user(authorization)
    u = storage.get_user(user)
    if not u["totp_secret"]:
        raise HTTPException(409, "primero llama a /auth/2fa/setup")
    if not access.verify_totp(user, u["totp_secret"], req.code):
        raise HTTPException(401, "código inválido")
    cluster.write("totp_enable", username=user)
    return {"ok": True}


class DisableRequest(BaseModel):
    password: str
    code: Optional[str] = None


@router.post("/auth/2fa/disable")
def totp_disable(req: DisableRequest, authorization: str = Header(None)):
    user = _user(authorization)
    u = storage.get_user(user)
    if not access.verify_password(req.password, u["password_hash"]):
        raise HTTPException(401, "contraseña incorrecta")
    if u["totp_enabled"] and not access.verify_totp(user, u["totp_secret"], req.code):
        raise HTTPException(401, "código 2FA inválido")
    cluster.write("totp_disable", username=user)
    return {"ok": True}


# api keys

class ApiKeyCreate(BaseModel):
    label: str = Field(default="", max_length=64)


@router.post("/auth/apikeys")
def apikey_create(req: ApiKeyCreate, authorization: str = Header(None)):
    user = _user(authorization)
    key_id, secret = uuid.uuid4().hex[:12], secrets.token_hex(16)
    cluster.write("create_apikey", key_id=key_id, owner=user, secret_hash=hashlib.sha256(secret.encode()).hexdigest(),
                  label=req.label, now=time.time())
    return {"key_id": key_id, "key": f"dfk_{key_id}_{secret}",
            "note": "guarda la clave: no se vuelve a mostrar"}


@router.get("/auth/apikeys")
def apikey_list(authorization: str = Header(None)):
    return {"keys": storage.list_apikeys(_user(authorization))}


class ApiKeyDelete(BaseModel):
    key_id: str


@router.post("/auth/apikeys/revoke")
def apikey_revoke(req: ApiKeyDelete, authorization: str = Header(None)):
    if not cluster.write("delete_apikey", key_id=req.key_id, owner=_user(authorization)):
        raise HTTPException(404, "esa API key no existe")
    return {"ok": True}


# grupos

class GroupCreate(BaseModel):
    name: str = Field(pattern=_GROUP_RE)


@router.post("/groups")
def group_create(req: GroupCreate, authorization: str = Header(None)):
    user = _user(authorization)
    if not cluster.write("create_group", name=req.name, owner=user):
        raise HTTPException(409, "el grupo ya existe")
    return {"ok": True}


@router.get("/groups")
def group_list(authorization: str = Header(None)):
    user = _user(authorization)
    return {"groups": [storage.get_group(g) for g in sorted(storage.groups_of(user))]}


def _own_group(name: str, user: str) -> dict:
    g = storage.get_group(name)
    if g is None:
        raise HTTPException(404, "el grupo no existe")
    if g["owner"] != user:
        raise HTTPException(403, "solo el dueño del grupo puede administrarlo")
    return g


class MemberRequest(BaseModel):
    username: str
    action: str = Field(pattern=r"^(add|remove)$")


@router.post("/groups/{name}/members")
def group_members(name: str, req: MemberRequest, authorization: str = Header(None)):
    user = _user(authorization)
    g = _own_group(name, user)
    if req.action == "add":
        if not storage.user_exists(req.username):
            raise HTTPException(404, "ese usuario no existe")
    elif req.username == g["owner"]:
        raise HTTPException(409, "el dueño no puede salir de su propio grupo")
    cluster.write("group_member", name=name, username=req.username, add=req.action == "add")
    return storage.get_group(name)


@router.post("/groups/{name}/delete")
def group_delete(name: str, authorization: str = Header(None)):
    _own_group(name, _user(authorization))
    cluster.write("delete_group", name=name)
    return {"ok": True}


# acl (compartir archivos y directorios)

class AclSet(BaseModel):
    path: str
    principal: str = Field(pattern=r"^(user|group):[A-Za-z0-9_.-]{2,32}$")
    perm: str = Field(pattern=r"^(r|rw|none)$")


def _path_exists(path: str) -> bool:
    return storage.get_dir_owner(path) is not None or storage.get_file(path) is not None


@router.post("/acl/set")
def acl_set(req: AclSet, authorization: str = Header(None)):
    """da, cambia o quita ('none') el permiso de un usuario o grupo sobre un archivo o directorio, solo puede quien es dueño del elemento (o de un directorio que lo contiene)"""
    user = _user(authorization)
    path = access.norm(req.path)
    if path == "/" or not _path_exists(path):
        raise HTTPException(404, "ese path no existe")
    access.require_level(path, user, access.OWNER, what="compartir este elemento")
    kind, name = req.principal.split(":", 1)
    if req.perm != "none":
        if kind == "user" and not storage.user_exists(name):
            raise HTTPException(404, "ese usuario no existe")
        if kind == "group" and storage.get_group(name) is None:
            raise HTTPException(404, "ese grupo no existe")
    cluster.write("set_acl", path=path, principal=req.principal, perm=req.perm)
    return {"ok": True}


@router.get("/acl")
def acl_get(path: str, authorization: str = Header(None)):
    user = _user(authorization)
    path = access.norm(path)
    if not _path_exists(path):
        raise HTTPException(404, "ese path no existe")
    access.require_level(path, user, access.OWNER, what="ver los permisos de este elemento")
    return {"path": path, "acl": storage.acl_for(path)}


@router.get("/acl/shared")
def acl_shared(authorization: str = Header(None)):
    """lo que otros compartieron conmigo (directo o por un grupo mío)"""
    user = _user(authorization)
    out = []
    for e in storage.shared_with(access.principals(user)):
        owner = storage.get_dir_owner(e["path"])
        f = storage.get_file(e["path"]) if owner is None else None
        if owner is None and f is None:
            continue
        out.append({**e, "type": "dir" if owner is not None else "file",
                    "owner": owner if owner is not None else f["owner"]})
    return {"shared": out}
