from __future__ import annotations

import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor

from app import db
from app.dns import aliyun, dnspod, wix
from app.dns.errors import DnsError
from app.dns.http import effective_proxy, normalize_proxy
from app.dns.nscheck import classify, query_ns

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "SPF", "HTTPS", "SVCB"]
PROVIDERS = {
    "aliyun": "阿里云",
    "tencent": "腾讯云 DNSPod",
    "dnspod": "DNSPod Token",
    "wix": "Wix",
}
ALIYUN_LINES = [
    ("default", "默认"),
    ("telecom", "电信"),
    ("unicom", "联通"),
    ("mobile", "移动"),
    ("oversea", "境外"),
    ("edu", "教育网"),
]
DNSPOD_LINES = [
    ("默认", "默认"),
    ("电信", "电信"),
    ("联通", "联通"),
    ("移动", "移动"),
    ("境外", "境外"),
]


def provider_label(provider: str) -> str:
    return PROVIDERS.get(provider, provider)


def provider_family(provider: str) -> str:
    if provider == "aliyun":
        return "aliyun"
    if provider == "wix":
        return "wix"
    if provider in {"tencent", "dnspod"}:
        return "dnspod"
    return ""


def ns_family(location: str, ns_provider: str) -> str:
    text = ns_provider or ""
    if location == "阿里DNS" or (location == "解析在外站" and "阿里" in text):
        return "aliyun"
    if location == "Wix" or (location == "解析在外站" and "Wix" in text):
        return "wix"
    if location == "DNSPod" or (location == "解析在外站" and ("DNSPod" in text or "腾讯" in text)):
        return "dnspod"
    return ""


def live_zone(zone: dict, zones: list[dict]) -> dict | None:
    family = ns_family(zone.get("ns_location") or "", zone.get("ns_provider") or "")
    if not family or provider_family(zone.get("provider") or "") == family:
        return None
    domain = (zone.get("domain") or "").strip().lower()
    candidates = [
        item
        for item in zones
        if item.get("site_id") != zone.get("site_id")
        and (item.get("domain") or "").strip().lower() == domain
        and provider_family(item.get("provider") or "") == family
    ]
    if not candidates:
        return None
    same_name = [item for item in candidates if item.get("site_name") == zone.get("site_name")]
    chosen = (same_name or candidates)[0]
    chosen_family = ns_family(chosen.get("ns_location") or "", chosen.get("ns_provider") or "")
    if chosen_family and provider_family(chosen.get("provider") or "") != chosen_family:
        return None
    return chosen


def record_types_for(provider: str) -> list[str]:
    if provider == "wix":
        return list(wix.RECORD_TYPES)
    return list(RECORD_TYPES)


def line_options(provider: str, current: str = "") -> list[tuple[str, str]]:
    if provider == "aliyun":
        options = list(ALIYUN_LINES)
    elif provider == "wix":
        options = [("默认", "默认")]
    else:
        options = list(DNSPOD_LINES)
    if current and current not in {item[0] for item in options}:
        options.append((current, current))
    return options


def line_label(provider: str, value: str) -> str:
    for key, label in line_options(provider, value or ""):
        if key == value:
            return label
    return value or "—"


def default_line(provider: str) -> str:
    return "default" if provider == "aliyun" else "默认"


def proxy_for(site: dict) -> str | None:
    return effective_proxy(site, db.get_setting("global_proxy"))


def credential_hint(provider: str, access_key: str) -> str:
    key = (access_key or "").strip()
    if provider == "tencent" and key.isdigit() and 4 <= len(key) <= 12:
        return "这看起来是 DNSPod Token ID，不是腾讯云 SecretId。服务商请改成 DNSPod Token。"
    if provider == "wix" and key.upper().startswith("IST."):
        return "这看起来是 API Key，不是 Account ID。Account ID 填上面，Authorization 填下面。"
    return ""


def explain_auth_error(provider: str, access_key: str, message: str) -> str:
    hint = credential_hint(provider, access_key)
    if hint:
        return hint
    text = message or ""
    lowered = text.lower()
    if "secretid" in lowered and any(word in lowered for word in ("not found", "notfound", "not exist", "invalid")):
        return "SecretId 不存在，请核对腾讯云密钥。"
    if "secretid" in text and "不存在" in text:
        return "SecretId 不存在，请核对腾讯云密钥。"
    whitelist = (
        "accesspolicydenied" in lowered
        or "forbidden.ram" in lowered
        or "not authorized" in lowered
        or "whitelist" in lowered
        or ("ip" in lowered and any(word in lowered for word in ("denied", "forbid", "not allow")))
    )
    if whitelist:
        return "这个出口 IP 不在白名单里，或密钥没有 DNS 权限。给这个平台填代理，或把当前 IP 加进白名单。"
    return text


def probe_site(site: dict) -> None:
    hint = credential_hint(site.get("provider") or "", site.get("access_key") or "")
    if hint:
        raise DnsError(hint)
    if os.environ.get("DNS_AUTO_SYNC") == "0":
        return
    try:
        _client(site).probe(site, proxy_for(site))
    except DnsError as exc:
        raise DnsError(explain_auth_error(site.get("provider") or "", site.get("access_key") or "", exc.message)) from exc


def validate_proxy(value: str) -> str:
    try:
        return normalize_proxy(value)
    except ValueError as exc:
        raise DnsError(str(exc)) from exc


def sync_site_catalog(site: dict) -> int:
    proxy = proxy_for(site)
    try:
        zones = _client(site).list_zones(site, proxy)
    except DnsError as exc:
        db.mark_site_sync(site["id"], exc.message)
        raise
    db.replace_zones(site["id"], zones)
    db.mark_site_sync(site["id"], "")
    return len(zones)


def sync_site(site: dict) -> tuple[int, int]:
    proxy = proxy_for(site)
    try:
        zones = _client(site).list_zones(site, proxy)
    except DnsError as exc:
        db.mark_site_sync(site["id"], exc.message)
        raise
    db.replace_zones(site["id"], zones)
    record_total = _cache_records(site, [zone["domain"] for zone in zones])
    db.mark_site_sync(site["id"], "")
    return len(zones), record_total


def sync_all() -> list[dict]:
    results = []
    for site in db.list_sites():
        try:
            domains, records = sync_site(site)
            results.append({"site": site["name"], "count": domains, "records": records, "error": ""})
        except DnsError as exc:
            results.append({"site": site["name"], "count": 0, "records": 0, "error": exc.message})
    return results


_rev_lock = threading.Lock()
_revs: dict[tuple[int, str], int] = {}


def revision(site_id: int, domain: str) -> int:
    with _rev_lock:
        return _revs.get((site_id, domain.lower()), 0)


def invalidate_zone(site_id: int, domain: str) -> None:
    key = (site_id, domain.lower())
    with _rev_lock:
        _revs[key] = _revs.get(key, 0) + 1


def refresh_domain_records(site: dict, domain: str) -> int:
    invalidate_zone(site["id"], domain)
    rev = revision(site["id"], domain)
    records = fetch_records(site, domain)
    if revision(site["id"], domain) != rev:
        return len(records)
    db.replace_records(site["id"], domain, records)
    return len(records)


def _cache_records(site: dict, domains: list[str]) -> int:
    if not domains:
        return 0

    def fetch_one(domain: str):
        rev = revision(site["id"], domain)
        try:
            return domain, fetch_records(site, domain), "", rev
        except DnsError as exc:
            return domain, None, exc.message, rev

    total = 0
    with ThreadPoolExecutor(max_workers=4) as executor:
        for domain, records, error, rev in executor.map(fetch_one, domains):
            if revision(site["id"], domain) != rev:
                continue
            if error:
                db.mark_records_error(site["id"], domain, error)
                continue
            db.replace_records(site["id"], domain, records or [])
            total += len(records or [])
    return total


def check_site_ns(site_id: int) -> None:
    zones = db.list_zones(site_id)
    if not zones:
        return

    def _one(zone: dict) -> None:
        outcome = inspect_ns(zone["provider"], zone["domain"])
        db.update_zone_ns(
            site_id,
            zone["domain"],
            ";".join(outcome["servers"]),
            outcome["location"],
            outcome["provider"],
        )

    with ThreadPoolExecutor(max_workers=12) as executor:
        list(executor.map(_one, zones))


def inspect_ns(provider: str, domain: str) -> dict:
    status, hosts = query_ns(domain)
    return classify(provider, status, hosts)


def normalize_query(value: str) -> str:
    text = (value or "").strip().lower()
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = text.split("/")[0].split("?")[0]
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    elif ":" in text:
        text = text.split(":")[0]
    return text.strip().rstrip(".")


def to_idna(name: str) -> str:
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


def match_zones(query: str, zones: list[dict] | None = None) -> list[dict]:
    needle = to_idna(normalize_query(query))
    if not needle:
        return []
    found = []
    for zone in zones if zones is not None else db.list_zones():
        domain = to_idna(zone["domain"].strip().lower().rstrip("."))
        if needle == domain or needle.endswith("." + domain):
            found.append(zone)
    if not found:
        return []
    best = max(len(to_idna(zone["domain"].strip().lower().rstrip("."))) for zone in found)
    return [
        zone
        for zone in found
        if len(to_idna(zone["domain"].strip().lower().rstrip("."))) == best
    ]


def choose_zone(matches: list[dict]) -> dict | None:
    if not matches:
        return None
    live = []
    for zone in matches:
        family = ns_family(zone.get("ns_location") or "", zone.get("ns_provider") or "")
        if family and provider_family(zone.get("provider") or "") == family:
            live.append(zone)
    if len(live) == 1:
        return live[0]
    for zone in matches:
        target = live_zone(zone, matches)
        if target:
            return target
    if len(matches) == 1:
        return matches[0]
    return None


def relative_host(query: str, domain: str) -> str:
    needle = to_idna(normalize_query(query))
    zone = to_idna(domain.strip().lower().rstrip("."))
    if not needle or needle == zone:
        return "@" if needle == zone else ""
    if needle.endswith("." + zone):
        return needle[: -(len(zone) + 1)]
    return ""


def fetch_records(site: dict, domain: str) -> list[dict]:
    return _client(site).list_records(site, domain, proxy_for(site))


def add_record(site: dict, domain: str, record: dict) -> None:
    _client(site).add_record(site, domain, record, proxy_for(site))


def update_record(site: dict, domain: str, record: dict) -> None:
    _client(site).update_record(site, domain, record, proxy_for(site))


def delete_record(site: dict, domain: str, record_id: str) -> None:
    _client(site).delete_record(site, domain, record_id, proxy_for(site))


def record_enabled(status: str) -> bool:
    return (status or "").strip().lower() in {"enable", "1"}


def set_record_status(site: dict, domain: str, record_id: str, enabled: bool) -> None:
    _client(site).set_record_status(site, domain, record_id, enabled, proxy_for(site))


def parse_record(form, provider: str) -> dict:
    host = (form.get("host") or "").strip()
    record_type = (form.get("type") or "").strip().upper()
    value = (form.get("value") or "").strip()
    line = (form.get("line") or "").strip() or default_line(provider)
    priority_raw = (form.get("priority") or "").strip()
    ttl_raw = (form.get("ttl") or "").strip() or "600"
    if not host:
        raise DnsError("请填写主机记录，根域名填 @。")
    if record_type not in record_types_for(provider):
        raise DnsError("不支持的记录类型。")
    if not value:
        raise DnsError("请填写记录值。")
    try:
        ttl = int(ttl_raw)
    except ValueError as exc:
        raise DnsError("TTL 要是整数。") from exc
    if ttl < 1 or ttl > 86400:
        raise DnsError("TTL 需要在 1 到 86400 之间。")
    priority = None
    if priority_raw:
        try:
            priority = int(priority_raw)
        except ValueError as exc:
            raise DnsError("优先级要是整数。") from exc
    elif record_type in {"MX", "SRV"}:
        priority = 10
    remark = "" if provider == "wix" else (form.get("remark") or "").strip()
    if len(remark) > 200:
        raise DnsError("备注最多 200 个字。")
    return {
        "id": (form.get("record_id") or "").strip(),
        "host": host,
        "type": record_type,
        "value": value,
        "ttl": ttl,
        "line": line,
        "priority": priority,
        "remark": remark,
    }


def _client(site: dict):
    if site["provider"] == "aliyun":
        return aliyun
    if site["provider"] == "wix":
        return wix
    if site["provider"] in {"tencent", "dnspod"}:
        return dnspod
    raise DnsError("未知的 DNS 服务商。")
