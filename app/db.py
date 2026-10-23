from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    path = Path(os.environ.get("DNS_DATA_DIR", str(ROOT / "data")))
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    return data_dir() / "dns.db"


SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    access_key TEXT NOT NULL,
    secret_key TEXT NOT NULL,
    proxy TEXT NOT NULL DEFAULT '',
    remark TEXT NOT NULL DEFAULT '',
    last_sync_at TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS zones (
    site_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    record_count INTEGER NOT NULL DEFAULT 0,
    dns_servers TEXT NOT NULL DEFAULT '',
    ns_public TEXT NOT NULL DEFAULT '',
    ns_location TEXT NOT NULL DEFAULT '',
    ns_provider TEXT NOT NULL DEFAULT '',
    ns_checked_at TEXT NOT NULL DEFAULT '',
    records_synced_at TEXT NOT NULL DEFAULT '',
    records_error TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (site_id, domain),
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS records (
    site_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    record_id TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT '',
    value TEXT NOT NULL DEFAULT '',
    ttl INTEGER NOT NULL DEFAULT 600,
    line TEXT NOT NULL DEFAULT '',
    priority INTEGER,
    status TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT '',
    remark TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (site_id, domain, record_id),
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_records_lookup ON records(site_id, domain);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    link TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_id ON audit_logs(id);
"""

_ready: set[str] = set()


def connect() -> sqlite3.Connection:
    path = str(db_path())
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if path not in _ready:
        conn.executescript(SCHEMA)
        _migrate(conn)
        _ready.add(path)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(zones)")}
    if "records_synced_at" not in columns:
        conn.execute("ALTER TABLE zones ADD COLUMN records_synced_at TEXT NOT NULL DEFAULT ''")
    if "records_error" not in columns:
        conn.execute("ALTER TABLE zones ADD COLUMN records_error TEXT NOT NULL DEFAULT ''")
    record_columns = {row["name"] for row in conn.execute("PRAGMA table_info(records)")}
    if "created_at" not in record_columns:
        conn.execute("ALTER TABLE records ADD COLUMN created_at TEXT NOT NULL DEFAULT ''")
    if "updated_at" not in record_columns:
        conn.execute("ALTER TABLE records ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")
    if "remark" not in record_columns:
        conn.execute("ALTER TABLE records ADD COLUMN remark TEXT NOT NULL DEFAULT ''")
    audit_columns = {row["name"] for row in conn.execute("PRAGMA table_info(audit_logs)")}
    if audit_columns and "link" not in audit_columns:
        conn.execute("ALTER TABLE audit_logs ADD COLUMN link TEXT NOT NULL DEFAULT ''")
    if audit_columns and "ip" not in audit_columns:
        conn.execute("ALTER TABLE audit_logs ADD COLUMN ip TEXT NOT NULL DEFAULT ''")


def init() -> None:
    with connect():
        return


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def record_stamp(value) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if not text or text in {"-", "—"}:
        return ""
    if text.isdigit():
        number = int(text)
        if number > 10_000_000_000:
            number //= 1000
        try:
            return datetime.fromtimestamp(number).strftime("%Y-%m-%d %H:%M:%S")
        except (OverflowError, OSError, ValueError):
            return ""
    return text.replace("T", " ")[:19]


def get_setting(key: str, default: str = "") -> str:
    with connect() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def delete_setting(key: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM settings WHERE key = ?", (key,))


def password_set() -> bool:
    return bool(get_setting("password_hash") and get_setting("password_salt"))


def clear_legacy_password() -> None:
    delete_setting("password_hash")
    delete_setting("password_salt")


def has_users() -> bool:
    with connect() as conn:
        row = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
    return row is not None


def list_users() -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, username, created_at FROM users ORDER BY id"
        ).fetchall()
    return [dict(row) for row in rows]


def get_user(user_id: int) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def get_user_by_name(username: str) -> dict | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username.strip(),),
        ).fetchone()
    return dict(row) if row else None


def first_user_id() -> int | None:
    with connect() as conn:
        row = conn.execute("SELECT MIN(id) AS id FROM users").fetchone()
    if not row or row["id"] is None:
        return None
    return int(row["id"])


def count_users() -> int:
    with connect() as conn:
        return int(conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"])


def create_user(username: str, salt: str, digest: str) -> int:
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO users(username, password_salt, password_hash, created_at)
            VALUES(?, ?, ?, ?)
            """,
            (username, salt, digest, now()),
        )
        return int(cursor.lastrowid)


def set_user_password(user_id: int, salt: str, digest: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE users SET password_salt = ?, password_hash = ? WHERE id = ?",
            (salt, digest, user_id),
        )


def delete_user(user_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


def add_audit(username: str, action: str, detail: str = "", link: str = "", ip: str = "") -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO audit_logs(created_at, username, action, detail, link, ip) VALUES(?, ?, ?, ?, ?, ?)",
            (now(), username or "—", action, (detail or "")[:300], link or "", (ip or "")[:64]),
        )


def query_audit(keyword: str = "", page: int = 1, page_size: int = 20):
    where = []
    args: list = []
    keyword = keyword.strip()
    if keyword:
        where.append(
            "(username LIKE ? ESCAPE '\\' OR action LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\' OR ip LIKE ? ESCAPE '\\')"
        )
        like = _like(keyword)
        args.extend([like, like, like, like])
    sql_where = ("WHERE " + " AND ".join(where)) if where else ""
    with connect() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) AS n FROM audit_logs {sql_where}", args
        ).fetchone()["n"]
        pages = max(1, (total + page_size - 1) // page_size)
        page = min(max(page, 1), pages)
        rows = conn.execute(
            f"""
            SELECT id, created_at, username, action, detail, link, ip
            FROM audit_logs
            {sql_where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            [*args, page_size, (page - 1) * page_size],
        ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["created_at"] = (item["created_at"] or "").replace("T", " ")
        items.append(item)
    return items, int(total), page, pages


def list_sites() -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM sites ORDER BY name COLLATE NOCASE, id").fetchall()
    return [dict(row) for row in rows]


def get_site(site_id: int) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    return dict(row) if row else None


def create_site(data: dict) -> int:
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO sites(name, provider, access_key, secret_key, proxy, remark, created_at)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["name"],
                data["provider"],
                data["access_key"],
                data["secret_key"],
                data.get("proxy") or "",
                data.get("remark") or "",
                now(),
            ),
        )
        return int(cursor.lastrowid)


def update_site(site_id: int, data: dict) -> None:
    with connect() as conn:
        conn.execute(
            """
            UPDATE sites
            SET name = ?, provider = ?, access_key = ?, secret_key = ?, proxy = ?, remark = ?
            WHERE id = ?
            """,
            (
                data["name"],
                data["provider"],
                data["access_key"],
                data["secret_key"],
                data.get("proxy") or "",
                data.get("remark") or "",
                site_id,
            ),
        )


def delete_site(site_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM records WHERE site_id = ?", (site_id,))
        conn.execute("DELETE FROM zones WHERE site_id = ?", (site_id,))
        conn.execute("DELETE FROM sites WHERE id = ?", (site_id,))


def mark_site_sync(site_id: int, error: str = "") -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE sites SET last_sync_at = ?, last_error = ? WHERE id = ?",
            (now(), error, site_id),
        )


def zone_counts() -> dict[int, int]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT site_id, COUNT(*) AS total FROM zones GROUP BY site_id"
        ).fetchall()
    return {int(row["site_id"]): int(row["total"]) for row in rows}


ATTENTION_LOCATIONS = ("NS查询失败", "解析在外站", "公网未委托", "域名不存在")


def attention_zones(limit: int = 8) -> tuple[list[dict], int]:
    marks = ",".join("?" for _ in ATTENTION_LOCATIONS)
    with connect() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) AS n FROM zones WHERE ns_location IN ({marks})",
            ATTENTION_LOCATIONS,
        ).fetchone()["n"]
        rows = conn.execute(
            f"""
            SELECT zones.site_id, zones.domain, zones.ns_location, zones.ns_provider,
                   sites.name AS site_name
            FROM zones JOIN sites ON sites.id = zones.site_id
            WHERE zones.ns_location IN ({marks})
            ORDER BY CASE zones.ns_location
                WHEN 'NS查询失败' THEN 0
                WHEN '解析在外站' THEN 1
                ELSE 2
            END, zones.domain COLLATE NOCASE
            LIMIT ?
            """,
            (*ATTENTION_LOCATIONS, limit),
        ).fetchall()
    return [dict(row) for row in rows], int(total)


def replace_zones(site_id: int, zones: list[dict]) -> None:
    with connect() as conn:
        existing = {
            row["domain"]: dict(row)
            for row in conn.execute("SELECT * FROM zones WHERE site_id = ?", (site_id,))
        }
        kept = [zone["domain"] for zone in zones if zone.get("domain")]
        if kept:
            marks = ",".join("?" for _ in kept)
            conn.execute(
                f"DELETE FROM records WHERE site_id = ? AND domain NOT IN ({marks})",
                [site_id, *kept],
            )
        else:
            conn.execute("DELETE FROM records WHERE site_id = ?", (site_id,))
        conn.execute("DELETE FROM zones WHERE site_id = ?", (site_id,))
        for zone in zones:
            old = existing.get(zone["domain"], {})
            conn.execute(
                """
                INSERT INTO zones(
                    site_id, domain, record_count, dns_servers,
                    ns_public, ns_location, ns_provider, ns_checked_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    site_id,
                    zone["domain"],
                    int(zone["record_count"])
                    if zone.get("record_count") is not None
                    else int(old.get("record_count") or 0),
                    zone.get("dns_servers") or "",
                    old.get("ns_public") or "",
                    old.get("ns_location") or "",
                    old.get("ns_provider") or "",
                    old.get("ns_checked_at") or "",
                ),
            )


def list_zones(site_id: int | None = None) -> list[dict]:
    with connect() as conn:
        if site_id is None:
            rows = conn.execute(
                """
                SELECT zones.*, sites.name AS site_name, sites.provider AS provider
                FROM zones JOIN sites ON sites.id = zones.site_id
                ORDER BY zones.domain COLLATE NOCASE
                """
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT zones.*, sites.name AS site_name, sites.provider AS provider
                FROM zones JOIN sites ON sites.id = zones.site_id
                WHERE zones.site_id = ?
                ORDER BY zones.domain COLLATE NOCASE
                """,
                (site_id,),
            ).fetchall()
    return [dict(row) for row in rows]


def get_zone(site_id: int, domain: str) -> dict | None:
    with connect() as conn:
        row = conn.execute(
            """
            SELECT zones.*, sites.name AS site_name, sites.provider AS provider
            FROM zones JOIN sites ON sites.id = zones.site_id
            WHERE zones.site_id = ? AND zones.domain = ?
            """,
            (site_id, domain),
        ).fetchone()
    return dict(row) if row else None


def _like(keyword: str) -> str:
    escaped = keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def zone_location_counts(site_id: int) -> dict[str, int]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT ns_location, COUNT(*) AS n FROM zones WHERE site_id = ? GROUP BY ns_location",
            (site_id,),
        ).fetchall()
    counts: dict[str, int] = {}
    for row in rows:
        key = row["ns_location"] or "未检查"
        if key == "域名不存在":
            key = "公网未委托"
        counts[key] = counts.get(key, 0) + int(row["n"])
    return counts


def own_ns_location(provider: str) -> str:
    if provider == "aliyun":
        return "阿里DNS"
    if provider == "wix":
        return "Wix"
    return "DNSPod"


def query_zones(
    site_id: int,
    keyword: str = "",
    location: str = "",
    page: int = 1,
    page_size: int = 20,
    provider: str = "",
):
    where = ["zones.site_id = ?"]
    args: list = [site_id]
    keyword = keyword.strip()
    if keyword:
        where.append("zones.domain LIKE ? ESCAPE '\\'")
        args.append(_like(keyword))
    if location == "live":
        own = own_ns_location(provider)
        where.append("(zones.ns_location = ? OR zones.ns_location = '')")
        args.append(own)
    elif location == "未检查":
        where.append("zones.ns_location = ''")
    elif location == "公网未委托":
        where.append("zones.ns_location IN ('公网未委托', '域名不存在')")
    elif location:
        where.append("zones.ns_location = ?")
        args.append(location)
    sql_where = " AND ".join(where)
    with connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS n FROM zones WHERE {sql_where}", args).fetchone()["n"]
        pages = max(1, (total + page_size - 1) // page_size)
        page = min(max(page, 1), pages)
        rows = conn.execute(
            f"""
            SELECT zones.*, sites.name AS site_name, sites.provider AS provider
            FROM zones JOIN sites ON sites.id = zones.site_id
            WHERE {sql_where}
            ORDER BY zones.domain COLLATE NOCASE
            LIMIT ? OFFSET ?
            """,
            [*args, page_size, (page - 1) * page_size],
        ).fetchall()
    return [dict(row) for row in rows], int(total), page, pages


def replace_records(site_id: int, domain: str, records: list[dict]) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM records WHERE site_id = ? AND domain = ?", (site_id, domain))
        for record in records:
            conn.execute(
                """
                INSERT INTO records(
                    site_id, domain, record_id, host, type, value, ttl, line, priority, status,
                    created_at, updated_at, remark
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    site_id,
                    domain,
                    str(record.get("id") or ""),
                    record.get("host") or "",
                    record.get("type") or "",
                    record.get("value") or "",
                    int(record.get("ttl") or 600),
                    record.get("line") or "",
                    record.get("priority"),
                    record.get("status") or "",
                    record_stamp(record.get("created_at")) or "—",
                    record_stamp(record.get("updated_at")) or "—",
                    (record.get("remark") or "").strip() or "—",
                ),
            )
        conn.execute(
            """
            UPDATE zones
            SET record_count = ?, records_synced_at = ?, records_error = ''
            WHERE site_id = ? AND domain = ?
            """,
            (len(records), now(), site_id, domain),
        )


def mark_records_error(site_id: int, domain: str, error: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE zones SET records_error = ? WHERE site_id = ? AND domain = ?",
            (error, site_id, domain),
        )


def records_missing_times(site_id: int, domain: str) -> bool:
    with connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM records WHERE site_id = ? AND domain = ? AND (updated_at = '' OR remark = '') LIMIT 1",
            (site_id, domain),
        ).fetchone()
    return row is not None


def get_record(site_id: int, domain: str, record_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM records WHERE site_id = ? AND domain = ? AND record_id = ?",
            (site_id, domain, record_id),
        ).fetchone()
    return _record(row) if row else None


def query_records(site_id: int, domain: str, keyword: str = "", page: int = 1, page_size: int = 20):
    where = ["site_id = ?", "domain = ?"]
    args: list = [site_id, domain]
    keyword = keyword.strip()
    if keyword:
        where.append("(host LIKE ? ESCAPE '\\' OR type LIKE ? ESCAPE '\\' OR value LIKE ? ESCAPE '\\' OR line LIKE ? ESCAPE '\\')")
        like = _like(keyword)
        args.extend([like, like, like, like])
    sql_where = " AND ".join(where)
    with connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS n FROM records WHERE {sql_where}", args).fetchone()["n"]
        pages = max(1, (total + page_size - 1) // page_size)
        page = min(max(page, 1), pages)
        rows = conn.execute(
            f"""
            SELECT * FROM records
            WHERE {sql_where}
            ORDER BY CASE WHEN host = '@' THEN 0 ELSE 1 END, host COLLATE NOCASE, type, record_id
            LIMIT ? OFFSET ?
            """,
            [*args, page_size, (page - 1) * page_size],
        ).fetchall()
    return [_record(row) for row in rows], int(total), page, pages


def _record(row: sqlite3.Row) -> dict:
    item = dict(row)
    item["id"] = item.pop("record_id")
    return item


def update_zone_ns(site_id: int, domain: str, public: str, location: str, provider: str) -> None:
    with connect() as conn:
        conn.execute(
            """
            UPDATE zones
            SET ns_public = ?, ns_location = ?, ns_provider = ?, ns_checked_at = ?
            WHERE site_id = ? AND domain = ?
            """,
            (public, location, provider, now(), site_id, domain),
        )
