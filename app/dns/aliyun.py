from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

from app.dns.errors import DnsError
from app.dns.http import request

ENDPOINT = "https://alidns.aliyuncs.com/"
API_VERSION = "2015-01-09"


def percent_encode(value) -> str:
    return quote(str(value), safe="-_.~")


def sign(params: dict, secret: str) -> str:
    canonical = "&".join(
        f"{percent_encode(key)}={percent_encode(params[key])}" for key in sorted(params)
    )
    string_to_sign = "GET&%2F&" + percent_encode(canonical)
    digest = hmac.new(
        (secret + "&").encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha1,
    ).digest()
    return base64.b64encode(digest).decode("utf-8")


def call(access_key: str, secret: str, action: str, extra: dict, proxy: str | None) -> dict:
    params = {
        "Action": action,
        "Format": "JSON",
        "Version": API_VERSION,
        "AccessKeyId": access_key,
        "SignatureMethod": "HMAC-SHA1",
        "SignatureVersion": "1.0",
        "SignatureNonce": str(uuid.uuid4()),
        "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    params.update({key: str(value) for key, value in extra.items() if value is not None})
    params["Signature"] = sign(params, secret)
    query = "&".join(
        f"{percent_encode(key)}={percent_encode(params[key])}" for key in sorted(params)
    )
    response = request("GET", ENDPOINT + "?" + query, proxy=proxy, headers={"Accept": "application/json"})
    try:
        payload = response.json()
    except json.JSONDecodeError as exc:
        raise DnsError("阿里云 DNS 返回了无法解析的内容。", response.text[:300]) from exc
    if "Code" in payload:
        detail = f"{payload.get('Code')}: {payload.get('Message', '')}"
        raise DnsError(detail, detail)
    return payload


def _as_list(value) -> list:
    if not value:
        return []
    if isinstance(value, list):
        return value
    return [value]


def dns_servers(domain: dict) -> str:
    raw = domain.get("DnsServers") or {}
    if isinstance(raw, dict):
        servers = _as_list(raw.get("DnsServer"))
    else:
        servers = _as_list(raw)
    return ";".join(str(item).rstrip(".").lower() for item in servers if item)


def probe(site: dict, proxy: str | None) -> None:
    call(site["access_key"], site["secret_key"], "DescribeDomains", {"PageNumber": 1, "PageSize": 1}, proxy)


def list_zones(site: dict, proxy: str | None) -> list[dict]:
    zones = []
    page = 1
    while True:
        payload = call(
            site["access_key"],
            site["secret_key"],
            "DescribeDomains",
            {"PageNumber": page, "PageSize": 100},
            proxy,
        )
        batch = _as_list((payload.get("Domains") or {}).get("Domain"))
        for item in batch:
            zones.append(
                {
                    "domain": item.get("DomainName") or "",
                    "record_count": int(item.get("RecordCount") or 0),
                    "dns_servers": dns_servers(item),
                }
            )
        total = int(payload.get("TotalCount") or 0)
        if len(zones) >= total or not batch:
            break
        page += 1
    return [zone for zone in zones if zone["domain"]]


def list_records(site: dict, domain: str, proxy: str | None) -> list[dict]:
    records = []
    page = 1
    while True:
        payload = call(
            site["access_key"],
            site["secret_key"],
            "DescribeDomainRecords",
            {"DomainName": domain, "PageNumber": page, "PageSize": 100},
            proxy,
        )
        batch = _as_list((payload.get("DomainRecords") or {}).get("Record"))
        records.extend(_record(item) for item in batch)
        total = int(payload.get("TotalCount") or 0)
        if len(records) >= total or not batch:
            break
        page += 1
    return records


def _record(item: dict) -> dict:
    priority = item.get("Priority")
    return {
        "id": str(item.get("RecordId") or ""),
        "host": item.get("RR") or "",
        "type": item.get("Type") or "",
        "value": item.get("Value") or "",
        "ttl": int(item.get("TTL") or 600),
        "line": item.get("Line") or "default",
        "priority": int(priority) if priority not in (None, "") else None,
        "status": item.get("Status") or "",
        "created_at": item.get("CreateTimestamp") or "",
        "updated_at": item.get("UpdateTimestamp") or "",
        "remark": item.get("Remark") or "",
    }


def add_record(site: dict, domain: str, record: dict, proxy: str | None) -> None:
    extra = {
        "DomainName": domain,
        "RR": record["host"],
        "Type": record["type"],
        "Value": record["value"],
        "TTL": record["ttl"],
        "Line": record["line"] or "default",
    }
    if record.get("priority") is not None:
        extra["Priority"] = record["priority"]
    if record.get("remark"):
        extra["Remark"] = record["remark"]
    call(site["access_key"], site["secret_key"], "AddDomainRecord", extra, proxy)


def update_record(site: dict, domain: str, record: dict, proxy: str | None) -> None:
    extra = {
        "RecordId": record["id"],
        "RR": record["host"],
        "Type": record["type"],
        "Value": record["value"],
        "TTL": record["ttl"],
        "Line": record["line"] or "default",
    }
    if record.get("priority") is not None:
        extra["Priority"] = record["priority"]
    call(site["access_key"], site["secret_key"], "UpdateDomainRecord", extra, proxy)
    call(
        site["access_key"],
        site["secret_key"],
        "UpdateDomainRecordRemark",
        {"RecordId": record["id"], "Remark": record.get("remark") or ""},
        proxy,
    )


def set_record_status(site: dict, domain: str, record_id: str, enabled: bool, proxy: str | None) -> None:
    call(
        site["access_key"],
        site["secret_key"],
        "SetDomainRecordStatus",
        {"RecordId": record_id, "Status": "Enable" if enabled else "Disable"},
        proxy,
    )


def delete_record(site: dict, domain: str, record_id: str, proxy: str | None) -> None:
    call(
        site["access_key"],
        site["secret_key"],
        "DeleteDomainRecord",
        {"RecordId": record_id},
        proxy,
    )
