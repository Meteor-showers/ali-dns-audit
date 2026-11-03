from __future__ import annotations

import hashlib
import hmac
import secrets

from app import db

PBKDF2_ROUNDS = 200_000


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, digest_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return hmac.compare_digest(digest.hex(), digest_hex)


def check_password(password: str) -> bool:
    salt = db.get_setting("password_salt")
    digest = db.get_setting("password_hash")
    if not salt or not digest:
        return False
    return verify_password(password, salt, digest)


def authenticate(username: str, password: str) -> dict | None:
    user = db.get_user_by_name(username)
    if not user or not verify_password(password, user["password_salt"], user["password_hash"]):
        return None
    return {"id": int(user["id"]), "username": user["username"]}


def directory_user(profile: dict) -> dict | None:
    username = str(profile.get("username") or "").strip()
    if not username or any(ch.isspace() for ch in username) or len(username) > 64:
        return None
    existing = db.get_user_by_name(username)
    if existing:
        db.update_user_profile(int(existing["id"]), str(profile.get("name") or ""), str(profile.get("email") or ""))
        return {"id": int(existing["id"]), "username": existing["username"]}
    salt, digest = hash_password(secrets.token_urlsafe(32))
    user_id = db.create_user(
        username,
        salt,
        digest,
        "ldap",
        str(profile.get("name") or ""),
        str(profile.get("email") or ""),
    )
    return {"id": user_id, "username": username}


def login(username: str, password: str) -> dict | None:
    from app import ldap_auth

    name = username.strip()
    if not name or not password or any(ch.isspace() for ch in name) or len(name) > 64:
        return None
    if not ldap_auth.enabled():
        return authenticate(name, password)
    admin_id = db.first_user_id()
    admin = db.get_user(admin_id) if admin_id else None
    if admin and admin["username"].lower() == name.lower():
        return authenticate(name, password)
    profile = ldap_auth.verify(name, password)
    if not profile:
        return None
    return directory_user(profile)


def create_user(username: str, password: str) -> dict:
    salt, digest = hash_password(password)
    user_id = db.create_user(username, salt, digest)
    return {"id": user_id, "username": username}


def set_password(user_id: int, password: str) -> None:
    salt, digest = hash_password(password)
    db.set_user_password(user_id, salt, digest)


def check_user_password(user_id: int, password: str) -> bool:
    user = db.get_user(user_id)
    if not user:
        return False
    return verify_password(password, user["password_salt"], user["password_hash"])
