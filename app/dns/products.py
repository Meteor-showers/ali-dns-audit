from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import threading
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from email.utils import formatdate
from xml.etree import ElementTree

from app import db
from app.dns.aliyun import rpc
from app.dns.errors import DnsError
from app.dns.http import request

TIMEOUT = 8.0
ORDER = ["CDN", "全站加速", "视频直播", "视频点播", "OSS", "负载均衡", "边缘安全加速", "API 网关"]
ACCELERATE = (
    ("CDN", "https://cdn.aliyuncs.com/", "2018-05-10", "DescribeUserDomains"),
    ("全站加速", "https://dcdn.aliyuncs.com/", "2018-01-15", "DescribeDcdnUserDomains"),
    ("视频直播", "https://live.aliyuncs.com/", "2016-11-01", "DescribeLiveUserDomains"),
    ("视频点播", "https://vod.cn-shanghai.aliyuncs.com/", "2017-03-21", "DescribeVodUserDomains"),
)


def covers(pattern: str, name: str) -> bool:
    pattern = (pattern or "").strip().lower().rstrip(".")
    name = (name or "").strip().lower().rstrip(".")
    if not pattern or not name:
        return False
    if pattern.startswith("*."):
        suffix = pattern[1:]
        if not name.endswith(suffix) or name == pattern[2:]:
            return False
        return "." not in name[: -len(suffix)]
    return pattern == name


def lookup_names(domain: str) -> list[str]:
    name = (domain or "").strip().lower().rstrip(".")
    if not name:
        return []
    names = [name]
    if name.count(".") >= 2 and not name.startswith("*."):
        names.append("*." + name.split(".", 1)[1])
    return names


def usage_phrase(found: list[tuple[str, str]]) -> str:
    grouped: dict[str, list[str]] = {}
    loose = []
    for site_name, product in found:
        if not site_name:
            if product not in loose:
                loose.append(product)
            continue
        bucket = grouped.setdefault(site_name, [])
        if product not in bucket:
            bucket.append(product)
    parts = []
    for site_name, products in grouped.items():
        products.sort(key=lambda item: ORDER.index(item) if item in ORDER else len(ORDER))
        parts.append(f"在{site_name}的 {'、'.join(products)} 使用")
    loose.sort(key=lambda item: ORDER.index(item) if item in ORDER else len(ORDER))
    parts.extend(loose)
    return "，".join(parts)


def hints_for(value: str) -> set[str]:
    host = (value or "").strip().lower().rstrip(".")
    if not host or _is_ip(host):
        return set()
    if host.endswith(".alb.aliyuncsslb.com") or host.endswith(".alb.aliyuncsslbintl.com") or host.endswith(".alb.aliyuncs.com"):
        return {"alb"}
    if host.endswith(".nlb.aliyuncsslb.com") or host.endswith(".nlb.aliyuncsslbintl.com") or host.endswith(".nlb.aliyuncs.com"):
        return {"nlb"}
    if ".oss-" in host and host.endswith(".aliyuncs.com"):
        return {"oss"}
    if host.endswith(".alicloudapi.com") or ".apig." in host:
        return {"apig"}
    if host.endswith(".inittt.com") or re.search(r"(^|\.)init[a-z]{2}\.com$", host):
        return {"esa"}
    if (
        host.endswith(".cdngslb.com")
        or host.endswith(".alikunlun.com")
        or host.endswith(".alikunlun.net")
        or re.search(r"(^|\.)kunlun[a-z0-9]*\.com$", host)
    ):
        return {"accelerate"}
    return set()


def host_fqdn(host: str, zone: str) -> str:
    zone_name = (zone or "").strip().lower().rstrip(".")
    name = (host or "").strip().lower()
    if name in {"", "@"}:
        return zone_name
    return f"{name}.{zone_name}"


def labels_for_name(fqdn: str, catalog: dict[str, set[str]]) -> list[str]:
    exact = []
    wild = []
    for label, names in catalog.items():
        if fqdn in names:
            exact.append(label)
        elif any(covers(item, fqdn) for item in names if item.startswith("*.")):
            wild.append(label)
    chosen = exact or wild
    chosen.sort(key=lambda item: ORDER.index(item) if item in ORDER else len(ORDER))
    return chosen


def row_groups(records: list[dict]) -> dict[str, list[str]]:
    buckets: dict[str, list[tuple[bool, str]]] = {}
    for row in records:
        if (row.get("type") or "").upper() not in {"A", "AAAA", "CNAME"}:
            continue
        host = (row.get("host") or "").strip().lower()
        value = (row.get("value") or "").strip()
        if not host or not value:
            continue
        enabled = (row.get("status") or "").strip().lower() in {"", "enable", "1"}
        buckets.setdefault(host, []).append((enabled, value))
    grouped = {}
    for host, pairs in buckets.items():
        enabled_values = [value for enabled, value in pairs if enabled]
        values = enabled_values or [value for _, value in pairs]
        grouped[host] = list(dict.fromkeys(values))
    return grouped


def fingerprint(values: list[str], accounts: list[tuple[dict, str | None]]) -> str:
    cleaned = sorted({item.strip().lower().rstrip(".") for item in values if item and item.strip()})
    ids = sorted(str(site.get("id") or site.get("name") or "") for site, _proxy in accounts)
    return "|".join(cleaned) + "\n" + ",".join(ids)


def domain_listed(payload: dict, name: str) -> bool:
    domains = payload.get("Domains") or {}
    rows = domains.get("PageData") if isinstance(domains, dict) else domains
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        return False
    wanted = name.lower().rstrip(".")
    return any(str(item.get("DomainName") or "").lower().rstrip(".") == wanted for item in rows if isinstance(item, dict))


def _is_ip(value: str) -> bool:
    if ":" in value:
        return True
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def _kind(exc: DnsError) -> str:
    text = f"{exc.detail} {exc.message}".lower()
    if "invalidaccesskey" in text or "signaturedoesnotmatch" in text:
        return "auth"
    if any(word in text for word in ("forbidden", "nopermission", "unauthorized", "not authorized", "accessdenied")):
        return "deny"
    return "error"


def _call(key: str, secret: str, endpoint: str, version: str, action: str, extra: dict, proxy: str | None) -> dict:
    return rpc(key, secret, endpoint, version, action, extra, proxy, timeout=TIMEOUT)


def _one_product(key: str, secret: str, proxy: str | None, name: str, spec: tuple) -> tuple[str, bool, str]:
    label, endpoint, version, action = spec
    try:
        payload = _call(
            key,
            secret,
            endpoint,
            version,
            action,
            {"DomainName": name, "DomainSearchType": "full_match", "PageSize": 10, "PageNumber": 1},
            proxy,
        )
    except DnsError as exc:
        return label, False, _kind(exc)
    return label, domain_listed(payload, name), "ok"


def _accelerate(key: str, secret: str, proxy: str | None, domain: str) -> tuple[list[str], str]:
    hits = []
    state = "error"
    for name in lookup_names(domain):
        if hits:
            break
        with ThreadPoolExecutor(max_workers=len(ACCELERATE)) as pool:
            futures = [pool.submit(_one_product, key, secret, proxy, name, spec) for spec in ACCELERATE]
            for future in as_completed(futures):
                label, matched, kind = future.result()
                if kind == "auth":
                    return hits, "auth"
                if kind == "ok":
                    state = "ok"
                    if matched:
                        hits.append(label)
                elif state != "ok":
                    state = kind
    return hits, state if hits or state == "ok" else state


def _endpoint_parts(value: str, marker: str) -> tuple[str, str] | None:
    host = (value or "").strip().lower().rstrip(".")
    parts = host.split(".")
    if len(parts) < 4 or marker not in parts:
        return None
    return parts[0], parts[1]


def _confirm_balancer(key: str, secret: str, proxy: str | None, value: str, kind: str) -> tuple[bool, str]:
    parsed = _endpoint_parts(value, kind)
    if not parsed:
        return False, "ok"
    lb_id, region = parsed
    endpoint = f"https://{kind}.{region}.aliyuncs.com/"
    version = "2020-06-16" if kind == "alb" else "2022-04-30"
    try:
        _call(key, secret, endpoint, version, "GetLoadBalancerAttribute", {"LoadBalancerId": lb_id}, proxy)
    except DnsError as exc:
        return False, _kind(exc)
    return True, "ok"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def oss_cnames(text: str) -> list[str]:
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return []
    names = []
    for node in root.iter():
        if _local(node.tag) == "Domain" and node.text:
            names.append(node.text.strip())
    return names


def _oss_sign(secret: str, resource: str, date: str) -> str:
    raw = f"GET\n\n\n{date}\n{resource}"
    digest = hmac.new(secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(digest).decode("utf-8")


def _confirm_oss(key: str, secret: str, proxy: str | None, value: str) -> tuple[bool, str]:
    host = (value or "").strip().lower().rstrip(".")
    if not host.endswith(".aliyuncs.com") or ".oss-" not in host:
        return False, "ok"
    left = host[: -len(".aliyuncs.com")]
    bucket, mark, location = left.partition(".oss-")
    if not bucket or not mark or not location:
        return False, "ok"
    endpoint = f"oss-{location}.aliyuncs.com"
    resource = f"/{bucket}?cname"
    date = formatdate(usegmt=True)
    try:
        response = request(
            "GET",
            f"https://{endpoint}{resource}",
            proxy=proxy,
            timeout=TIMEOUT,
            headers={"Date": date, "Authorization": f"OSS {key}:{_oss_sign(secret, resource, date)}"},
        )
    except DnsError as exc:
        return False, _kind(exc)
    if response.status_code >= 400 or "<Error>" in response.text[:200]:
        code = ""
        message = ""
        try:
            root = ElementTree.fromstring(response.text)
        except ElementTree.ParseError:
            return False, "error"
        for node in root.iter():
            if _local(node.tag) == "Code":
                code = node.text or ""
            elif _local(node.tag) == "Message":
                message = node.text or ""
        return False, _kind(DnsError(f"{code}: {message}", f"{code}: {message}"))
    return True, "ok"


def _account(site: dict, proxy: str | None, domain: str, values: list[str]) -> tuple[list[tuple[str, str]], str]:
    wanted: set[str] = set()
    for value in values:
        wanted.update(hints_for(value))
    if not wanted:
        return [], "ok"
    key = site.get("access_key") or ""
    secret = site.get("secret_key") or ""
    name = site.get("name") or "阿里云"
    found = []
    state = ""
    if "accelerate" in wanted:
        labels, state = _accelerate(key, secret, proxy, domain)
        if state == "auth":
            return found, "auth"
        found.extend((name, label) for label in labels)
    for kind in ("alb", "nlb"):
        if kind not in wanted:
            continue
        for value in values:
            if kind not in hints_for(value):
                continue
            hit, kind_state = _confirm_balancer(key, secret, proxy, value, kind)
            if kind_state == "auth":
                return found, "auth"
            if kind_state == "ok":
                state = "ok"
            elif state != "ok":
                state = kind_state
            if hit:
                found.append((name, "负载均衡"))
                break
    if "oss" in wanted:
        for value in values:
            if "oss" not in hints_for(value):
                continue
            hit, oss_state = _confirm_oss(key, secret, proxy, value)
            if oss_state == "auth":
                return found, "auth"
            if oss_state == "ok":
                state = "ok"
            elif state != "ok":
                state = oss_state
            if hit:
                found.append((name, "OSS"))
                break
    return found, state


def _pending(accounts: list[tuple[dict, str | None]], domain: str, values: list[str] | None) -> tuple[list[str], str | None]:
    cleaned = [item for item in (values or []) if item and item.strip()]
    if os.environ.get("DNS_PRODUCT_LOOKUP") == "0" or not domain or not cleaned:
        return cleaned, ""
    if not accounts or not any(hints_for(value) for value in cleaned):
        return cleaned, ""
    cached = db.read_usage(domain, fingerprint(cleaned, accounts))
    if cached is not None:
        return cleaned, cached
    return cleaned, None


class _Listing:
    def __init__(self, names: set[str], complete: bool, state: str) -> None:
        self.names = names
        self.complete = complete
        self.state = state


_flight_guard = threading.Lock()
_flights: dict[str, Future] = {}


def _account_id(site: dict) -> str:
    if site.get("id") is not None:
        return str(site.get("id"))
    return str(site.get("name") or "")


def _site_name(site: dict) -> str:
    return site.get("name") or "阿里云"


def _in_zone(name: str, zone: str) -> bool:
    name = (name or "").strip().lower().rstrip(".")
    zone = (zone or "").strip().lower().rstrip(".")
    return bool(zone) and (name == zone or name.endswith("." + zone))


def _page_rows(payload: dict) -> list:
    domains = payload.get("Domains") or {}
    rows = domains.get("PageData") if isinstance(domains, dict) else domains
    if isinstance(rows, dict):
        rows = [rows]
    return rows if isinstance(rows, list) else []


def _list_suffix(key: str, secret: str, proxy: str | None, zone: str, spec: tuple) -> tuple[str, set[str], str, bool]:
    label, endpoint, version, action = spec
    names: set[str] = set()
    state = "error"
    complete = False
    seen = 0
    for page in range(1, 4):
        try:
            payload = _call(
                key,
                secret,
                endpoint,
                version,
                action,
                {"DomainName": zone, "DomainSearchType": "suf_match", "PageSize": 500, "PageNumber": page},
                proxy,
            )
        except DnsError as exc:
            return label, names, _kind(exc), False
        state = "ok"
        rows = _page_rows(payload)
        seen += len(rows)
        for item in rows:
            if not isinstance(item, dict) or not item.get("DomainName"):
                continue
            domain_name = str(item["DomainName"]).lower().rstrip(".")
            if _in_zone(domain_name, zone):
                names.add(domain_name)
        total = int(payload.get("TotalCount") or 0)
        if not rows or (total and seen >= total) or (not total and len(rows) < 500):
            complete = True
            break
    return label, names, state, complete


def _load_catalogs(accounts: list[tuple[dict, str | None]], zone: str) -> dict[str, dict[str, _Listing]]:
    catalogs: dict[str, dict[str, _Listing]] = {}
    jobs = []
    for site, proxy in accounts:
        account_id = _account_id(site)
        bucket = catalogs.setdefault(account_id, {})
        for spec in ACCELERATE:
            cached = db.read_catalog(account_id, zone, spec[0])
            if cached is None:
                jobs.append((site, proxy, spec))
                continue
            names, complete = cached
            bucket[spec[0]] = _Listing(names, complete, "ok")
    if not jobs:
        return catalogs
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            pool.submit(
                _list_suffix,
                site.get("access_key") or "",
                site.get("secret_key") or "",
                proxy,
                zone,
                spec,
            ): (site, spec)
            for site, proxy, spec in jobs
        }
        for future in as_completed(futures):
            site, spec = futures[future]
            label, names, state, complete = future.result()
            kept = names if state == "ok" else set()
            done = complete if state == "ok" else False
            catalogs.setdefault(_account_id(site), {})[label] = _Listing(kept, done, state)
            if state == "ok":
                db.write_catalog(_account_id(site), zone, label, kept, done)
    return catalogs


def catalogs_for(accounts: list[tuple[dict, str | None]], zone: str) -> dict[str, dict[str, _Listing]]:
    zone_name = (zone or "").strip().lower().rstrip(".")
    key = zone_name + "\n" + ",".join(sorted(_account_id(site) for site, _proxy in accounts))
    with _flight_guard:
        flight = _flights.get(key)
        if flight is None:
            flight = Future()
            _flights[key] = flight
            leader = True
        else:
            leader = False
    if not leader:
        return flight.result()
    try:
        found = _load_catalogs(accounts, zone_name)
        flight.set_result(found)
        return found
    except BaseException as exc:
        flight.set_exception(exc)
        raise
    finally:
        with _flight_guard:
            if _flights.get(key) is flight:
                _flights.pop(key, None)


def _account_labels(fqdn: str, listings: dict[str, _Listing]) -> tuple[list[str], str]:
    exact = []
    wild = []
    saw_ok = False
    saw_deny = False
    saw_error = False
    uncertain = False
    for label, _endpoint, _version, _action in ACCELERATE:
        item = listings.get(label)
        if item is None or item.state != "ok":
            state = item.state if item else "error"
            if state == "deny":
                saw_deny = True
            else:
                saw_error = True
            uncertain = True
            continue
        saw_ok = True
        if not item.complete:
            uncertain = True
        if fqdn in item.names:
            exact.append(label)
        elif any(covers(name, fqdn) for name in item.names if name.startswith("*.")):
            wild.append(label)
    chosen = exact or wild
    chosen.sort(key=lambda item: ORDER.index(item) if item in ORDER else len(ORDER))
    if saw_ok and not uncertain:
        return chosen, "ok"
    if saw_ok:
        return chosen, "partial"
    if saw_deny and not saw_error:
        return chosen, "deny"
    return chosen, "error"


def _confirm_one(site: dict, proxy: str | None, kind: str, value: str) -> tuple[bool, str]:
    key = site.get("access_key") or ""
    secret = site.get("secret_key") or ""
    if kind == "oss":
        return _confirm_oss(key, secret, proxy, value)
    return _confirm_balancer(key, secret, proxy, value, kind)


def preview_usages(accounts: list[tuple[dict, str | None]], zone: str, records: list[dict]) -> tuple[dict[str, str], dict[str, bool]]:
    phrases = {}
    pending = {}
    for host, values in row_groups(records).items():
        _values, phrase = _pending(accounts, host_fqdn(host, zone), values)
        phrases[host] = "" if phrase is None else phrase
        pending[host] = phrase is None
    return phrases, pending


def load_usages(accounts: list[tuple[dict, str | None]], zone: str, records: list[dict]) -> dict[str, str]:
    grouped = row_groups(records)
    result = {}
    todo = []
    for host, values in grouped.items():
        fqdn = host_fqdn(host, zone)
        hints = set()
        for value in values:
            hints.update(hints_for(value))
        _values, phrase = _pending(accounts, fqdn, values)
        if phrase is None:
            todo.append((host, fqdn, values, hints))
        else:
            result[host] = phrase
    if not todo:
        return result
    need_catalog = any("accelerate" in hints for _host, _fqdn, _values, hints in todo)
    jobs = {}
    for _host, _fqdn, values, hints in todo:
        for kind in ("alb", "nlb", "oss"):
            if kind not in hints:
                continue
            for site, proxy in accounts:
                for value in values:
                    if kind not in hints_for(value):
                        continue
                    token = value.strip().lower().rstrip(".")
                    jobs[(_account_id(site), kind, token)] = (site, proxy, kind, token)
    confirm_results: dict[tuple[str, str, str], tuple[bool, str]] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        catalog_future = pool.submit(catalogs_for, accounts, zone) if need_catalog else None
        confirm_futures = {
            pool.submit(_confirm_one, site, proxy, kind, value): key
            for key, (site, proxy, kind, value) in jobs.items()
        }
        catalogs = catalog_future.result() if catalog_future else {}
        for future in as_completed(confirm_futures):
            key = confirm_futures[future]
            try:
                confirm_results[key] = future.result()
            except Exception:
                confirm_results[key] = (False, "error")
    for host, fqdn, values, hints in todo:
        accel_hits = []
        accel_statuses = []
        if "accelerate" in hints:
            for site, _proxy in accounts:
                labels, status = _account_labels(fqdn, catalogs.get(_account_id(site), {}))
                accel_statuses.append(status)
                for label in labels:
                    accel_hits.append((_site_name(site), label))
        confirm_hits = []
        confirm_states = []
        for kind in ("alb", "nlb", "oss"):
            if kind not in hints:
                continue
            product = "OSS" if kind == "oss" else "负载均衡"
            seen_sites = set()
            for site, _proxy in accounts:
                account_id = _account_id(site)
                for value in values:
                    if kind not in hints_for(value):
                        continue
                    token = value.strip().lower().rstrip(".")
                    hit, state = confirm_results.get((account_id, kind, token), (False, "error"))
                    confirm_states.append(state)
                    if hit and account_id not in seen_sites:
                        seen_sites.add(account_id)
                        confirm_hits.append((_site_name(site), product))
        local = []
        if "esa" in hints:
            local.append(("", "边缘安全加速"))
        if "apig" in hints:
            local.append(("", "API 网关"))
        found = accel_hits + confirm_hits + local
        accel_trust = "accelerate" not in hints or (
            bool(accel_statuses) and all(item == "ok" for item in accel_statuses)
        )
        confirm_trust = not confirm_states or all(item == "ok" for item in confirm_states)
        if not found and "accelerate" in hints and accel_statuses and not any(item in {"ok", "partial"} for item in accel_statuses):
            result[host] = "没有权限" if all(item == "deny" for item in accel_statuses) else "查询失败"
            continue
        if not found and confirm_states and not any(item == "ok" for item in confirm_states):
            result[host] = "没有权限" if all(item == "deny" for item in confirm_states) else "查询失败"
            continue
        phrase = usage_phrase(found)
        if accel_trust and confirm_trust:
            db.write_usage(fqdn, fingerprint(values, accounts), phrase)
        result[host] = phrase
    return result


def peek_usage(accounts: list[tuple[dict, str | None]], domain: str, values: list[str] | None = None) -> tuple[str, bool]:
    _cleaned, phrase = _pending(accounts, domain, values)
    if phrase is None:
        return "", True
    return phrase, False


def find_usage(accounts: list[tuple[dict, str | None]], domain: str, values: list[str] | None = None) -> str:
    values, cached = _pending(accounts, domain, values)
    if cached is not None:
        return cached
    token = fingerprint(values, accounts)
    found: list[tuple[str, str]] = []
    saw_ok = False
    saw_deny = False
    saw_error = False
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(_account, site, proxy, domain, values) for site, proxy in accounts]
        for future in as_completed(futures):
            try:
                hits, state = future.result()
            except DnsError as exc:
                hits, state = [], _kind(exc)
            found.extend(hits)
            if state == "auth":
                saw_error = True
            elif state == "ok":
                saw_ok = True
            elif state == "deny":
                saw_deny = True
            else:
                saw_error = True
    if any("esa" in hints_for(value) for value in values):
        found.append(("", "边缘安全加速"))
    if any("apig" in hints_for(value) for value in values):
        found.append(("", "API 网关"))
    if not saw_ok and saw_deny and not found:
        return "没有权限"
    if not saw_ok and saw_error and not found:
        return "查询失败"
    phrase = usage_phrase(found)
    db.write_usage(domain, token, phrase)
    return phrase
