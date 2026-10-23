from __future__ import annotations

import base64
import json
from urllib.parse import quote

from app.dns.errors import DnsError
from app.dns.http import request

CONNECTED = "https://www.wixapis.com/domains/v1/connected-domains"
REGISTERED = "https://www.wixapis.com/domains/v1/registered-domains"
RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "SPF"]
PRIORITY_TYPES = {"MX", "SRV"}
EXACT_TYPES = {"TXT", "SPF"}
CODE_TEXT = {
    "TARGET_ACCOUNT_NOT_FOUND": "Account ID 不对。请填 Wix 账号 ID，不是站点 ID。",
    "USER_ID_NOT_FOUND": "Authorization 没有通过。请填写账号级 API Key。",
    "UNAUTHENTICATED": "Authorization 没有通过。请填写账号级 API Key。",
    "PERMISSION_DENIED": "这个 API Key 没有域名权限。",
    "DOMAINS_PERMISSION_DENIED": "这个 API Key 没有这个账号的域名权限。",
    "DNS_ZONE_NOT_FOUND": "Wix 没有这个域名的解析。指向接入的域名不由 Wix 管理 DNS。",
    "DOMAIN_NOT_PERMITTED": "这个域名不属于当前 Account ID。",
    "DOMAIN_CNAME_RECORD_HOSTNAME_INVALID": "Wix 的 CNAME 只能写在子域名上，不能写根域名。",
    "DOMAIN_DNS_EMPTY_RECORD_VALUE": "记录值不能为空。",
}


class WixCallError(DnsError):
    def __init__(self, message: str, status: int = 0, code: str = ""):
        super().__init__(message)
        self.status = status
        self.code = code


def account_id(value: str) -> str:
    text = (value or "").strip()
    if text.lower().startswith("wix-account-id:"):
        text = text.split(":", 1)[1].strip()
    return text


def authorization_value(value: str) -> str:
    text = (value or "").strip()
    if text.lower().startswith("authorization:"):
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


def absolute_host(host: str, domain: str) -> str:
    host = (host or "").strip().rstrip(".").lower()
    domain = (domain or "").strip().rstrip(".").lower()
    if host in {"@", ""}:
        return domain
    if host == domain or host.endswith("." + domain):
        return host
    return f"{host}.{domain}"


def relative_host(host_name: str, domain: str) -> str:
    host_name = from_idna(host_key(host_name))
    domain = from_idna(host_key(domain))
    if not host_name or host_name == domain:
        return "@"
    suffix = "." + domain
    if host_name.endswith(suffix):
        return host_name[: -len(suffix)]
    return host_name


def split_priority(record_type: str, raw: str) -> tuple[int | None, str]:
    text = (raw or "").strip()
    if record_type not in PRIORITY_TYPES:
        return None, text
    parts = text.split(None, 1)
    if len(parts) == 2 and parts[0].isdigit():
        return int(parts[0]), parts[1]
    return None, text


def compose_value(record: dict) -> str:
    value = (record.get("value") or "").strip()
    if record.get("type") not in PRIORITY_TYPES:
        return value
    priority = record.get("priority")
    if priority is None:
        return value
    prefix = f"{priority} "
    if value.startswith(prefix):
        return value
    return f"{priority} {value}"


def make_id(record_type: str, host: str, value: str, priority: int | None) -> str:
    raw = json.dumps([record_type, host, value, priority], ensure_ascii=False, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_id(record_id: str) -> dict:
    try:
        pad = "=" * (-len(record_id) % 4)
        payload = json.loads(base64.urlsafe_b64decode((record_id + pad).encode()).decode())
        record_type, host, value, priority = payload
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise DnsError("这条解析记录已失效，请刷新后再改。") from exc
    return {
        "type": str(record_type or "").upper(),
        "host": str(host or ""),
        "value": str(value or ""),
        "priority": priority if isinstance(priority, int) else None,
        "ttl": 600,
        "line": "默认",
    }


def flatten_records(domain: str, raw_records: list) -> list[dict]:
    rows = []
    for item in raw_records or []:
        if not isinstance(item, dict):
            continue
        record_type = str(item.get("type") or "").upper()
        host_name = str(item.get("hostName") or "")
        if not record_type or not host_name:
            continue
        host = relative_host(host_name, domain)
        ttl = int(item.get("ttl") or 600)
        for raw in item.get("values") or []:
            priority, value = split_priority(record_type, str(raw))
            rows.append(
                {
                    "id": make_id(record_type, host, value, priority),
                    "host": host,
                    "type": record_type,
                    "value": value,
                    "ttl": ttl,
                    "line": "默认",
                    "priority": priority,
                    "status": "enable",
                    "created_at": "",
                    "updated_at": "",
                    "remark": "",
                }
            )
    return rows


def _same_value(record_type: str, raw: str, expected: str) -> bool:
    left = raw.strip()
    right = expected.strip()
    if record_type in EXACT_TYPES:
        return left == right
    return left.rstrip(".") == right.rstrip(".")


def _groups(raw_records: list) -> list[dict]:
    groups = []
    for item in raw_records or []:
        if not isinstance(item, dict):
            continue
        record_type = str(item.get("type") or "").upper()
        host_name = str(item.get("hostName") or "").strip()
        values = [str(value) for value in (item.get("values") or []) if str(value).strip()]
        if not record_type or not host_name or not values:
            continue
        groups.append(
            {
                "type": record_type,
                "hostName": host_name,
                "ttl": int(item.get("ttl") or 600),
                "values": values,
                "key": (record_type, host_key(host_name)),
            }
        )
    return groups


def _wire(group: dict, values: list[str] | None = None, ttl: int | None = None, host_name: str | None = None) -> dict:
    return {
        "type": group["type"],
        "hostName": host_name if host_name is not None else group["hostName"],
        "ttl": group["ttl"] if ttl is None else int(ttl),
        "values": list(group["values"] if values is None else values),
    }


def _find(groups: list[dict], record_type: str, host: str, domain: str) -> dict | None:
    key = (record_type, host_key(absolute_host(host, domain)))
    for group in groups:
        if group["key"] == key:
            return group
    return None


def _index(group: dict, record: dict) -> int:
    expected = compose_value(record)
    for index, raw in enumerate(group["values"]):
        if _same_value(group["type"], raw, expected):
            return index
    return -1


def _check_record(record: dict, domain: str) -> str:
    record_type = (record.get("type") or "").upper()
    if record_type not in RECORD_TYPES and record_type not in {"SOA", "PTR", "NAPTR"}:
        raise DnsError("Wix 不支持这个记录类型。")
    host_name = absolute_host(record.get("host") or "", domain)
    if record_type == "CNAME" and host_key(host_name) == host_key(domain):
        raise DnsError("Wix 的 CNAME 只能写在子域名上，不能写根域名。")
    if not compose_value(record):
        raise DnsError("记录值不能为空。")
    return host_name


def plan_change(domain: str, raw_records: list, op: str, record: dict, before: dict | None = None) -> dict:
    record = {**record, "type": str(record.get("type") or "").upper()}
    if before:
        before = {**before, "type": str(before.get("type") or "").upper()}
    groups = _groups(raw_records)
    deletions = []
    additions = []
    if op == "add":
        host_name = _check_record(record, domain)
        group = _find(groups, record["type"], record["host"], domain)
        value = compose_value(record)
        if group and _index(group, record) >= 0:
            raise DnsError("这条解析已经存在。")
        if group and len(group["values"]) >= 50:
            raise DnsError("Wix 同一个主机和类型最多 50 条记录值。")
        if group:
            deletions.append(_wire(group))
            additions.append(_wire(group, values=[*group["values"], value], ttl=record.get("ttl") or group["ttl"]))
        else:
            additions.append(
                {
                    "type": record["type"],
                    "hostName": to_idna(host_name),
                    "ttl": int(record.get("ttl") or 600),
                    "values": [value],
                }
            )
    elif op == "delete":
        group = _find(groups, before["type"], before["host"], domain) if before else None
        if not group or _index(group, before or record) < 0:
            raise DnsError("没有找到这条解析记录，请刷新后再试。")
        index = _index(group, before or record)
        kept = [value for number, value in enumerate(group["values"]) if number != index]
        if group["type"] in {"NS", "SOA"} and not kept:
            raise DnsError("Wix 的 NS 和 SOA 不能删光。")
        deletions.append(_wire(group))
        if kept:
            additions.append(_wire(group, values=kept))
    elif op == "update":
        if not before:
            raise DnsError("缺少记录 ID。")
        source = _find(groups, before["type"], before["host"], domain)
        if not source or _index(source, before) < 0:
            raise DnsError("没有找到这条解析记录，请刷新后再试。")
        host_name = _check_record(record, domain)
        target = _find(groups, record["type"], record["host"], domain)
        value = compose_value(record)
        index = _index(source, before)
        same_group = target is source
        if target and not same_group and _index(target, record) >= 0:
            raise DnsError("这条解析已经存在。")
        if same_group and any(_same_value(source["type"], raw, value) for number, raw in enumerate(source["values"]) if number != index):
            raise DnsError("这条解析已经存在。")
        if target and not same_group and len(target["values"]) >= 50:
            raise DnsError("Wix 同一个主机和类型最多 50 条记录值。")
        source_values = [item for number, item in enumerate(source["values"]) if number != index]
        if same_group:
            source_values.insert(index, value)
            if source["type"] in {"NS", "SOA"} and not source_values:
                raise DnsError("Wix 的 NS 和 SOA 不能删光。")
            deletions.append(_wire(source))
            if source_values:
                additions.append(_wire(source, values=source_values, ttl=record.get("ttl") or source["ttl"]))
        else:
            if source["type"] in {"NS", "SOA"} and not source_values:
                raise DnsError("Wix 的 NS 和 SOA 不能删光。")
            deletions.append(_wire(source))
            if source_values:
                additions.append(_wire(source, values=source_values))
            if target:
                deletions.append(_wire(target))
                additions.append(_wire(target, values=[*target["values"], value], ttl=record.get("ttl") or target["ttl"]))
            else:
                additions.append(
                    {
                        "type": record["type"],
                        "hostName": to_idna(host_name),
                        "ttl": int(record.get("ttl") or 600),
                        "values": [value],
                    }
                )
    else:
        raise DnsError("不支持的解析操作。")
    body = {}
    if deletions:
        body["deletions"] = deletions
    if additions:
        body["additions"] = additions
    return body


def _headers(site: dict) -> dict:
    return {
        "Authorization": authorization_value(site.get("secret_key") or ""),
        "wix-account-id": account_id(site.get("access_key") or ""),
        "Accept": "application/json",
    }


def _error_message(status: int, code: str, description: str) -> str:
    if code == "DOMAIN_MX_RECORD_VALUE_INVALID" and "hostName" in description:
        return "同一个主机和类型要合并成一条，不能拆开提交。"
    if code == "DOMAIN_MX_RECORD_VALUE_INVALID":
        return "MX 记录值要是「优先级 邮件服务器」，例如 10 aspmx.l.google.com。"
    if code in CODE_TEXT:
        return CODE_TEXT[code]
    if status in {401, 403}:
        return "Wix 拒绝了这个密钥。请检查 Account ID 和 Authorization。"
    if description:
        return description
    return f"Wix 请求失败（HTTP {status}）。"


def _fail(response) -> None:
    description = ""
    code = ""
    try:
        payload = response.json()
    except json.JSONDecodeError:
        if response.status_code == 404:
            raise WixCallError("Wix 没有这个接口。", status=404, code="NOT_FOUND")
        raise WixCallError(
            f"Wix 返回了无法解析的内容（HTTP {response.status_code}）。",
            status=response.status_code,
        )
    if isinstance(payload, dict):
        app = ((payload.get("details") or {}).get("applicationError") or {}) if isinstance(payload.get("details"), dict) else {}
        code = str(app.get("code") or "")
        description = str(app.get("description") or payload.get("message") or "")
    raise WixCallError(_error_message(response.status_code, code, description), status=response.status_code, code=code)


def _call(site: dict, method: str, url: str, proxy: str | None, params: dict | None = None, body: dict | None = None) -> dict:
    headers = _headers(site)
    if body is not None:
        headers["Content-Type"] = "application/json"
    response = request(method, url, proxy=proxy, headers=headers, params=params, json=body)
    if response.status_code >= 400:
        _fail(response)
    if not response.content:
        return {}
    try:
        payload = response.json()
    except json.JSONDecodeError as exc:
        raise DnsError("Wix 返回了无法解析的内容。", response.text[:300]) from exc
    return payload if isinstance(payload, dict) else {}


def _missing(exc: WixCallError) -> bool:
    return exc.status == 404 and exc.code in {"", "NOT_FOUND"}


def _domain_of(item: dict) -> str:
    for key in ("domain", "domainName", "id"):
        value = str(item.get(key) or "").strip().lower().rstrip(".")
        if "." in value and " " not in value and len(value) <= 253:
            return value
    return ""


def _batch(payload: dict) -> list:
    for key in ("connectedDomains", "registeredDomains", "domains"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return []


def _page(site: dict, url: str, proxy: str | None, cursor: str) -> dict:
    params = {"paging.limit": 100}
    if cursor:
        params["paging.cursor"] = cursor
    return _call(site, "GET", url, proxy, params=params)


def _collect(site: dict, url: str, proxy: str | None) -> list[dict]:
    cursor = ""
    seen: set[str] = set()
    found: list[dict] = []
    for _ in range(200):
        payload = _page(site, url, proxy, cursor)
        found.extend(item for item in _batch(payload) if isinstance(item, dict))
        meta = payload.get("pagingMetadata") or {}
        nxt = str((meta.get("cursors") or {}).get("next") or "")
        if not meta.get("hasNext") or not nxt or nxt in seen:
            break
        seen.add(nxt)
        cursor = nxt
    return found


def _zones_from(items: list[dict]) -> dict[str, dict]:
    zones = {}
    for item in items:
        name = _domain_of(item)
        if name:
            zones.setdefault(name, {"domain": name})
    return zones


def probe(site: dict, proxy: str | None) -> None:
    try:
        _page(site, CONNECTED, proxy, "")
        return
    except WixCallError as exc:
        if not _missing(exc):
            raise
    _page(site, REGISTERED, proxy, "")


def list_zones(site: dict, proxy: str | None) -> list[dict]:
    zones: dict[str, dict] = {}
    saw_list = False
    for url in (CONNECTED, REGISTERED):
        try:
            zones.update(_zones_from(_collect(site, url, proxy)))
            saw_list = True
        except WixCallError as exc:
            if url == REGISTERED and exc.status in {401, 403, 404}:
                continue
            if url == CONNECTED and _missing(exc):
                continue
            raise
    if not saw_list:
        raise DnsError("Wix 没有返回域名列表。")
    return [zones[name] for name in sorted(zones)]


def _zone_url(domain: str) -> str:
    return "https://www.wixapis.com/domains/v1/dns-zones/" + quote(host_key(domain), safe="")


def _load_raw(site: dict, domain: str, proxy: str | None) -> list:
    payload = _call(site, "GET", _zone_url(domain), proxy)
    zone = payload.get("dnsZone") if isinstance(payload.get("dnsZone"), dict) else payload
    records = zone.get("records") if isinstance(zone, dict) else []
    return records if isinstance(records, list) else []


def list_records(site: dict, domain: str, proxy: str | None) -> list[dict]:
    return flatten_records(domain, _load_raw(site, domain, proxy))


def _apply(site: dict, domain: str, proxy: str | None, op: str, record: dict, before: dict | None = None) -> None:
    raw = _load_raw(site, domain, proxy)
    body = plan_change(domain, raw, op, record, before)
    if not body:
        return
    body["domainName"] = host_key(domain)
    _call(site, "PATCH", _zone_url(domain), proxy, body=body)


def add_record(site: dict, domain: str, record: dict, proxy: str | None) -> None:
    _apply(site, domain, proxy, "add", record)


def update_record(site: dict, domain: str, record: dict, proxy: str | None) -> None:
    _apply(site, domain, proxy, "update", record, decode_id(record.get("id") or ""))


def delete_record(site: dict, domain: str, record_id: str, proxy: str | None) -> None:
    current = decode_id(record_id)
    _apply(site, domain, proxy, "delete", current, current)


def set_record_status(site: dict, domain: str, record_id: str, enabled: bool, proxy: str | None) -> None:
    raise DnsError("Wix 不能单独停止一条解析，只能修改或删除。")
