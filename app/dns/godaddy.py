from __future__ import annotations

import base64
import json
from urllib.parse import quote

from app.dns.errors import DnsError
from app.dns.http import request

API = "https://api.godaddy.com"
RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"]
PRIORITY_TYPES = {"MX", "SRV"}


def api_key(value: str) -> str:
    text = (value or "").strip()
    if text.lower().startswith("sso-key "):
        text = text.split(None, 1)[1].strip()
    if ":" in text:
        text = text.split(":", 1)[0].strip()
    return text


def api_secret(value: str) -> str:
    text = (value or "").strip()
    if text.lower().startswith("sso-key "):
        text = text.split(None, 1)[1].strip()
        if ":" in text:
            text = text.split(":", 1)[1].strip()
    return text


def to_idna(name: str) -> str:
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


def from_idna(name: str) -> str:
    try:
        return name.encode("ascii").decode("idna")
    except UnicodeError:
        return name


def host_key(name: str) -> str:
    return to_idna((name or "").strip().rstrip(".").lower())


def relative_name(name: str) -> str:
    text = from_idna((name or "").strip().rstrip(".").lower())
    return "@" if text in {"", "@"} else text


def make_id(record_type: str, host: str, value: str, priority: int | None) -> str:
    raw = json.dumps([record_type, host, value, priority], ensure_ascii=False, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_id(record_id: str) -> dict:
    try:
        pad = "=" * (-len(record_id) % 4)
        record_type, host, value, priority = json.loads(base64.urlsafe_b64decode((record_id + pad).encode()).decode())
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        raise DnsError("记录 ID 无法识别，请刷新后再试。") from exc
    return {"type": record_type, "host": host, "value": value, "priority": priority}


def _display_value(item: dict) -> str:
    data = str(item.get("data") or "").strip()
    if str(item.get("type") or "").upper() != "SRV":
        return data
    weight = int(item.get("weight") or 0)
    port = int(item.get("port") or 0)
    return f"{weight} {port} {data}".strip()


def _priority(item: dict) -> int | None:
    if str(item.get("type") or "").upper() not in PRIORITY_TYPES:
        return None
    raw = item.get("priority")
    if raw is None or raw == "":
        return None
    return int(raw)


def flatten_records(domain: str, raw: list) -> list[dict]:
    rows = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        record_type = str(item.get("type") or "").upper()
        if record_type in {"", "SOA"}:
            continue
        host = relative_name(str(item.get("name") or ""))
        value = _display_value({**item, "type": record_type})
        priority = _priority({**item, "type": record_type})
        rows.append(
            {
                "id": make_id(record_type, host, value, priority),
                "host": host,
                "type": record_type,
                "value": value,
                "ttl": int(item.get("ttl") or 600),
                "line": "默认",
                "priority": priority,
                "status": "enable",
                "remark": "",
                "created_at": "",
                "updated_at": "",
            }
        )
    rows.sort(key=lambda row: (row["host"], row["type"], row["value"]))
    return rows


def _srv_parts(value: str) -> tuple[int, int, str]:
    parts = value.split()
    if len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
        return int(parts[0]), int(parts[1]), " ".join(parts[2:])
    raise DnsError("SRV 记录值要是「权重 端口 目标」，例如 1 443 sip.example.com。")


def _stored(record: dict) -> dict:
    record_type = record["type"]
    value = (record.get("value") or "").strip()
    item = {"data": value, "ttl": int(record.get("ttl") or 600), "priority": record.get("priority")}
    if record_type == "SRV":
        weight, port, target = _srv_parts(value)
        item = {"data": target, "ttl": item["ttl"], "priority": item["priority"], "weight": weight, "port": port}
    return item


def _same(left: dict, right: dict) -> bool:
    return (
        left["type"] == right["type"]
        and relative_name(left["host"]) == relative_name(right["host"])
        and left["value"] == right["value"]
        and left.get("priority") == right.get("priority")
    )


def _check(record: dict, groups: dict[tuple[str, str], list[dict]]) -> None:
    host = relative_name(record.get("host") or "")
    record_type = record["type"]
    if record_type == "CNAME" and host == "@":
        raise DnsError("GoDaddy 的 CNAME 只能写在子域名上，不能写根域名。")
    others = [
        kind
        for (kind, name), values in groups.items()
        if name == host and values and (kind, name) != (record_type, host)
    ]
    if record_type == "CNAME" and others:
        raise DnsError("这个主机上已经有其他解析，不能再加 CNAME。")
    if record_type != "CNAME" and "CNAME" in others:
        raise DnsError("这个主机已经是 CNAME，不能再加其他解析。")


def _groups(raw: list) -> dict[tuple[str, str], list[dict]]:
    grouped: dict[tuple[str, str], list[dict]] = {}
    for row in flatten_records("", raw):
        grouped.setdefault((row["type"], row["host"]), []).append(row)
    return grouped


def _body(record_type: str, rows: list[dict]) -> list[dict]:
    payload = []
    for row in rows:
        stored = _stored(row)
        item = {"data": stored["data"], "ttl": max(600, int(stored["ttl"]))}
        if record_type in PRIORITY_TYPES and stored.get("priority") is not None:
            item["priority"] = int(stored["priority"])
        if record_type == "SRV":
            item["weight"] = int(stored["weight"])
            item["port"] = int(stored["port"])
        payload.append(item)
    return payload


def plan_change(domain: str, raw: list, op: str, record: dict, before: dict | None = None) -> list[dict]:
    groups = _groups(raw)
    record = {**record, "host": relative_name(record.get("host") or "")}
    if before:
        before = {**before, "host": relative_name(before.get("host") or "")}

    def find(wanted: dict) -> tuple[tuple[str, str], int] | None:
        key = (wanted["type"], wanted["host"])
        for index, row in enumerate(groups.get(key, [])):
            if _same(row, wanted):
                return key, index
        return None

    actions: list[tuple[str, str, list[dict]]] = []
    if op == "add":
        _check(record, groups)
        key = (record["type"], record["host"])
        rows = list(groups.get(key, []))
        if any(_same(row, record) for row in rows):
            raise DnsError("这条解析已经存在。")
        rows.append(record)
        actions.append((key[0], key[1], rows))
    elif op == "delete":
        found = find(before or record)
        if not found:
            raise DnsError("没有找到这条解析记录，请刷新后再试。")
        key, index = found
        kept = [row for number, row in enumerate(groups[key]) if number != index]
        if key == ("NS", "@") and not kept:
            raise DnsError("GoDaddy 根域名的 NS 不能删光。")
        actions.append((key[0], key[1], kept))
    elif op == "update":
        if not before:
            raise DnsError("缺少记录 ID。")
        found = find(before)
        if not found:
            raise DnsError("没有找到这条解析记录，请刷新后再试。")
        source_key, index = found
        groups[source_key] = [row for number, row in enumerate(groups[source_key]) if number != index]
        _check(record, groups)
        target_key = (record["type"], record["host"])
        target = list(groups.get(target_key, []))
        if any(_same(row, record) for row in target):
            raise DnsError("这条解析已经存在。")
        if source_key == ("NS", "@") and source_key != target_key and not groups[source_key]:
            raise DnsError("GoDaddy 根域名的 NS 不能删光。")
        target.append(record)
        source_action = None
        if source_key != target_key:
            source_action = (source_key[0], source_key[1], groups[source_key])
        # CNAME 不能和同主机的其他类型共存，所以先清掉旧类型再写入。
        # 其他改名先写新记录，避免后一步失败时把唯一的记录删掉。
        cname_swap = source_action and (record["type"] == "CNAME" or source_key[0] == "CNAME")
        if cname_swap:
            actions.append(source_action)
        actions.append((target_key[0], target_key[1], target))
        if source_action and not cname_swap:
            actions.append(source_action)
    else:
        raise DnsError("不支持的解析操作。")
    return [{"type": kind, "name": name, "records": rows} for kind, name, rows in actions]


def _headers(site: dict) -> dict:
    key = api_key(site.get("access_key") or "")
    secret = api_secret(site.get("secret_key") or "")
    if not key or not secret:
        raise DnsError("请填写 GoDaddy 的 API Key 和 Secret。")
    return {"Authorization": f"sso-key {key}:{secret}", "Accept": "application/json"}


def _message(status: int, payload) -> str:
    if not isinstance(payload, dict):
        return f"GoDaddy 请求失败（HTTP {status}）。"
    code = str(payload.get("code") or "")
    text = str(payload.get("message") or "")
    fields = payload.get("fields") if isinstance(payload.get("fields"), list) else []
    detail = "；".join(str(item.get("message") or "") for item in fields if isinstance(item, dict) and item.get("message"))
    if status in {401, 403} or code in {"UNABLE_TO_AUTHENTICATE", "ACCESS_DENIED"}:
        return "GoDaddy 拒绝了这个密钥。请检查 API Key 和 Secret。"
    if status == 404:
        return "GoDaddy 没有这个域名，或 DNS 不由 GoDaddy 管理。"
    if detail:
        return detail
    if text:
        return text
    return f"GoDaddy 请求失败（HTTP {status}）。"


def _call(site: dict, method: str, path: str, proxy: str | None, params: dict | None = None, body=None):
    headers = _headers(site)
    if body is not None:
        headers["Content-Type"] = "application/json"
    response = request(method, API + path, proxy=proxy, headers=headers, params=params, json=body)
    if response.status_code >= 400:
        try:
            payload = response.json()
        except json.JSONDecodeError:
            payload = {}
        raise DnsError(_message(response.status_code, payload))
    if not response.content:
        return []
    try:
        return response.json()
    except json.JSONDecodeError as exc:
        raise DnsError("GoDaddy 返回了无法解析的内容。", response.text[:300]) from exc


def _domain_path(domain: str) -> str:
    return "/v1/domains/" + quote(host_key(domain), safe="")


def probe(site: dict, proxy: str | None) -> None:
    _call(site, "GET", "/v1/domains", proxy, params={"statuses": "ACTIVE", "limit": 1})


def list_zones(site: dict, proxy: str | None) -> list[dict]:
    marker = ""
    seen: set[str] = set()
    names: list[str] = []
    for _ in range(50):
        params = {"statuses": "ACTIVE", "limit": 1000}
        if marker:
            params["marker"] = marker
        payload = _call(site, "GET", "/v1/domains", proxy, params=params)
        if not isinstance(payload, list) or not payload:
            break
        for item in payload:
            if not isinstance(item, dict):
                continue
            name = host_key(str(item.get("domain") or ""))
            if name and name not in seen:
                seen.add(name)
                names.append(from_idna(name))
        if len(payload) < 1000:
            break
        last = host_key(str(payload[-1].get("domain") or "")) if isinstance(payload[-1], dict) else ""
        if not last or last == marker:
            break
        marker = last
    return [{"domain": name} for name in sorted(names)]


def _load_raw(site: dict, domain: str, proxy: str | None) -> list:
    payload = _call(site, "GET", _domain_path(domain) + "/records", proxy)
    return payload if isinstance(payload, list) else []


def list_records(site: dict, domain: str, proxy: str | None) -> list[dict]:
    return flatten_records(domain, _load_raw(site, domain, proxy))


def _record_path(domain: str, record_type: str, name: str) -> str:
    # 根域名必须是 %40。GoDaddy 网关不认路径里未编码的 @。* 保持原样。
    host = quote(to_idna(name), safe="*")
    return f"{_domain_path(domain)}/records/{record_type}/{host}"


def _apply(site: dict, domain: str, proxy: str | None, op: str, record: dict, before: dict | None = None) -> None:
    raw = _load_raw(site, domain, proxy)
    for change in plan_change(domain, raw, op, record, before):
        path = _record_path(domain, change["type"], change["name"])
        if change["records"]:
            _call(site, "PUT", path, proxy, body=_body(change["type"], change["records"]))
        else:
            _call(site, "DELETE", path, proxy)


def add_record(site: dict, domain: str, record: dict, proxy: str | None) -> None:
    _apply(site, domain, proxy, "add", record)


def update_record(site: dict, domain: str, record: dict, proxy: str | None) -> None:
    _apply(site, domain, proxy, "update", record, decode_id(record.get("id") or ""))


def delete_record(site: dict, domain: str, record_id: str, proxy: str | None) -> None:
    before = decode_id(record_id)
    _apply(site, domain, proxy, "delete", before, before)


def set_record_status(site: dict, domain: str, record_id: str, enabled: bool, proxy: str | None) -> None:
    raise DnsError("GoDaddy 不能单独停止一条解析，只能修改或删除。")
