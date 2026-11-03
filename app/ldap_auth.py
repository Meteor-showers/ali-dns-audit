from __future__ import annotations

import json

from app import db
from app.dns.errors import DnsError

DEFAULT_FILTER = "(sAMAccountName=%(user)s)"
DEFAULT_MAP = {"username": "sAMAccountName", "name": "cn", "email": "mail"}
_KEYS = (
    "ldap_url",
    "ldap_ous",
    "ldap_base",
    "ldap_bind_dn",
    "ldap_bind_password",
    "ldap_filter",
    "ldap_attr_map",
    "ldap_enabled",
)


def enabled() -> bool:
    return db.get_setting("ldap_enabled") == "1" and bool(_saved_ous())


def public_config() -> dict:
    raw_map = db.get_setting("ldap_attr_map")
    return {
        "url": db.get_setting("ldap_url"),
        "bind_dn": db.get_setting("ldap_bind_dn"),
        "ous": db.get_setting("ldap_ous") or db.get_setting("ldap_base"),
        "user_filter": db.get_setting("ldap_filter") or DEFAULT_FILTER,
        "attr_map": raw_map or json.dumps(DEFAULT_MAP, ensure_ascii=False),
        "enabled": db.get_setting("ldap_enabled") == "1",
        "password_set": bool(db.get_setting("ldap_bind_password")),
    }


def parse(
    url: str,
    bind_dn: str,
    bind_password: str,
    ous: str,
    user_filter: str,
    attr_map: str,
    enabled_flag: bool,
    *,
    require_search: bool = False,
) -> dict:
    url = url.strip()
    bind_dn = bind_dn.strip()
    user_filter = user_filter.strip() or DEFAULT_FILTER
    bases = [item.strip() for item in ous.split("|") if item.strip()]
    mapping = _mapping(attr_map)
    if not url and not bases and not bind_dn and not enabled_flag:
        return {"clear": True}
    if url and not (url.startswith("ldap://") or url.startswith("ldaps://")):
        raise DnsError("LDAP 地址要以 ldap:// 或 ldaps:// 开头。")
    if url and any(mark in url for mark in (" ", "@", "?", "\\")):
        raise DnsError("LDAP 地址只填写主机和端口。")
    if "%(user)s" not in user_filter and "{username}" not in user_filter:
        raise DnsError("用户过滤器里要有 %(user)s。")
    password = bind_password or db.get_setting("ldap_bind_password")
    if bind_dn and not password:
        raise DnsError("填写了绑定 DN 时要填写密码。")
    if enabled_flag or require_search:
        if not url:
            raise DnsError("请填写 LDAP 地址。")
        if not bases:
            raise DnsError("请填写用户 OU，多个 OU 用 | 分隔。")
    return {
        "clear": False,
        "url": url,
        "bind_dn": bind_dn,
        "bind_password": password,
        "ous": bases,
        "ous_text": " | ".join(bases),
        "user_filter": user_filter,
        "attr_map": mapping,
        "attr_map_text": json.dumps(mapping, ensure_ascii=False),
        "enabled": enabled_flag,
    }


def store(config: dict) -> None:
    if config.get("clear"):
        _clear()
        return
    db.set_setting("ldap_url", config["url"])
    db.set_setting("ldap_ous", config["ous_text"])
    db.delete_setting("ldap_base")
    db.set_setting("ldap_bind_dn", config["bind_dn"])
    db.set_setting("ldap_bind_password", config["bind_password"])
    db.set_setting("ldap_filter", config["user_filter"])
    db.set_setting("ldap_attr_map", config["attr_map_text"])
    db.set_setting("ldap_enabled", "1" if config["enabled"] else "")


def test_connection(config: dict) -> str:
    if config.get("clear") or not config.get("url"):
        raise DnsError("请填写 LDAP 地址。")
    _bind(config).unbind()
    return "连接成功。"


def test_login(config: dict, username: str, password: str) -> str:
    if not username.strip() or not password:
        raise DnsError("请填写测试用户名和测试密码。")
    profile = authenticate(config, username, password)
    if not profile:
        raise DnsError("用户名或密码不正确。")
    return f"登录成功：{profile['username']}"


def verify(username: str, password: str) -> dict | None:
    if not enabled():
        return None
    config = parse(
        db.get_setting("ldap_url"),
        db.get_setting("ldap_bind_dn"),
        db.get_setting("ldap_bind_password"),
        _saved_ous(),
        db.get_setting("ldap_filter"),
        db.get_setting("ldap_attr_map"),
        True,
        require_search=True,
    )
    return authenticate(config, username, password)


def import_users(config: dict) -> tuple[int, int]:
    if config.get("clear"):
        raise DnsError("请先填写 LDAP 地址和用户 OU。")
    found = _collect(config, _fill(config["user_filter"], "*", escape=False))
    admin = db.get_user(db.first_user_id() or 0)
    admin_name = (admin or {}).get("username", "").lower()
    created = 0
    skipped = 0
    seen = set()
    for profile in found:
        username = profile["username"].strip()
        key = username.lower()
        if not username or key in seen or any(ch.isspace() for ch in username) or len(username) > 64:
            skipped += 1
            continue
        seen.add(key)
        existing = db.get_user_by_name(username)
        if key == admin_name or existing:
            if existing and key != admin_name:
                db.update_user_profile(int(existing["id"]), profile["name"], profile["email"])
            skipped += 1
            continue
        if created >= 2000:
            skipped += 1
            continue
        from app.auth import directory_user

        if directory_user(profile):
            created += 1
        else:
            skipped += 1
    return created, skipped


def authenticate(config: dict, username: str, password: str) -> dict | None:
    username = username.strip()
    if not username or not password or config.get("clear"):
        return None
    conn = _bind(config)
    try:
        found = _search(conn, config, _fill(config["user_filter"], username), limit=2)
    finally:
        conn.unbind()
    if len(found) != 1:
        return None
    profile, user_dn = found[0]
    if not _user_bind(config, user_dn, password):
        return None
    if not profile["username"]:
        profile["username"] = username
    return profile


def _collect(config: dict, search_filter: str) -> list[dict]:
    conn = _bind(config)
    try:
        rows = _search(conn, config, search_filter, limit=5000)
    finally:
        conn.unbind()
    return [profile for profile, _dn in rows if profile["username"]]


def _bind(config: dict):
    try:
        from ldap3 import Connection
        from ldap3.core.exceptions import LDAPBindError, LDAPException, LDAPSocketOpenError
    except ImportError as exc:
        raise DnsError("还没有安装 LDAP 组件。") from exc
    try:
        return Connection(
            _server(config["url"]),
            user=config.get("bind_dn") or None,
            password=config.get("bind_password") or None,
            auto_bind=True,
            receive_timeout=8,
            auto_referrals=False,
        )
    except LDAPBindError as exc:
        raise DnsError("绑定 DN 或密码不正确。") from exc
    except LDAPSocketOpenError as exc:
        raise DnsError("LDAP 服务器连不上。") from exc
    except LDAPException as exc:
        raise DnsError("LDAP 连接失败。") from exc


def _user_bind(config: dict, user_dn: str, password: str) -> bool:
    from ldap3 import Connection
    from ldap3.core.exceptions import LDAPBindError, LDAPException, LDAPSocketOpenError

    try:
        conn = Connection(
            _server(config["url"]),
            user=user_dn,
            password=password,
            auto_bind=True,
            receive_timeout=8,
            auto_referrals=False,
        )
    except LDAPBindError:
        return False
    except LDAPSocketOpenError as exc:
        raise DnsError("LDAP 服务器连不上。") from exc
    except LDAPException:
        return False
    conn.unbind()
    return True


def _search(conn, config: dict, search_filter: str, limit: int) -> list[tuple[dict, str]]:
    from ldap3 import SUBTREE
    from ldap3.core.exceptions import LDAPException

    attributes = [name for name in config["attr_map"].values() if name]
    found = []
    seen = set()
    try:
        for base in config["ous"]:
            cookie = None
            while len(found) < limit:
                conn.search(
                    base,
                    search_filter,
                    search_scope=SUBTREE,
                    attributes=attributes or ["1.1"],
                    paged_size=min(500, limit - len(found)),
                    paged_cookie=cookie,
                )
                for item in conn.response or []:
                    if item.get("type") == "searchResRef" or not item.get("dn"):
                        continue
                    dn = str(item["dn"]).lower()
                    if dn in seen:
                        continue
                    seen.add(dn)
                    found.append((_profile(item, config["attr_map"]), str(item["dn"])))
                    if len(found) >= limit:
                        break
                cookie = _cookie(conn)
                if not cookie:
                    break
    except LDAPException as exc:
        raise DnsError("LDAP 查询失败。") from exc
    return found


def _profile(item: dict, mapping: dict) -> dict:
    attributes = item.get("attributes") or {}
    return {
        "username": _value(attributes, mapping.get("username") or ""),
        "name": _value(attributes, mapping.get("name") or ""),
        "email": _value(attributes, mapping.get("email") or ""),
    }


def _value(attributes: dict, name: str) -> str:
    if not name:
        return ""
    raw = attributes.get(name)
    if isinstance(raw, list):
        raw = raw[0] if raw else ""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    return str(raw or "").strip()


def _cookie(conn) -> bytes | None:
    controls = (conn.result or {}).get("controls") or {}
    value = (controls.get("1.2.840.113556.1.4.319") or {}).get("value") or {}
    cookie = value.get("cookie")
    return cookie or None


def _fill(template: str, username: str, escape: bool = True) -> str:
    value = _escape(username) if escape else username
    return template.replace("%(user)s", value).replace("{username}", value)


def _mapping(raw: str) -> dict:
    text = raw.strip() or json.dumps(DEFAULT_MAP, ensure_ascii=False)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DnsError("LDAP 属性映射需要是 JSON，例如 {\"username\": \"sAMAccountName\", \"name\": \"cn\", \"email\": \"mail\"}。") from exc
    if not isinstance(parsed, dict):
        raise DnsError("LDAP 属性映射需要是 JSON 对象。")
    username = str(parsed.get("username") or "").strip()
    if not username:
        raise DnsError("属性映射里要有 username。")
    return {
        "username": username,
        "name": str(parsed.get("name") or "").strip(),
        "email": str(parsed.get("email") or "").strip(),
    }


def _saved_ous() -> str:
    return db.get_setting("ldap_ous") or db.get_setting("ldap_base")


def _clear() -> None:
    for key in _KEYS:
        db.delete_setting(key)


def _escape(value: str) -> str:
    return (
        value.replace("\\", r"\5c")
        .replace("*", r"\2a")
        .replace("(", r"\28")
        .replace(")", r"\29")
        .replace("\x00", r"\00")
    )


def _server(url: str):
    from ldap3 import NONE, Server

    secure = url.startswith("ldaps://")
    hostport = url.split("://", 1)[1]
    if hostport.startswith("["):
        end = hostport.find("]")
        if end < 0:
            raise DnsError("LDAP 地址不正确。")
        host = hostport[1:end]
        rest = hostport[end + 1 :]
        port_text = rest[1:] if rest.startswith(":") else ""
        if rest and not rest.startswith(":"):
            raise DnsError("LDAP 地址不正确。")
    else:
        if "/" in hostport:
            raise DnsError("LDAP 地址只填写主机和端口。")
        host, sep, port_text = hostport.rpartition(":")
        if not sep:
            host, port_text = hostport, ""
    if not host:
        raise DnsError("LDAP 地址不正确。")
    try:
        port = int(port_text) if port_text else (636 if secure else 389)
    except ValueError as exc:
        raise DnsError("LDAP 端口不正确。") from exc
    if not 1 <= port <= 65535:
        raise DnsError("LDAP 端口不正确。")
    return Server(host, port=port, use_ssl=secure, connect_timeout=8, get_info=NONE)
