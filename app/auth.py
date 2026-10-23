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
