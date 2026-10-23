from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from urllib.parse import urlencode

from app.dns.errors import DnsError
from app.dns.http import request

TENCENT_HOST = "dnspod.tencentcloudapi.com"
TENCENT_SERVICE = "dnspod"
TENCENT_VERSION = "2021-03-23"
TOKEN_ENDPOINT = "https://dnsapi.cn"


def _tc3_headers(secret_id: str, secret_key: str, action: str, body: str, timestamp: int) -> dict:
    date = datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d")
    content_type = "application/json; charset=utf-8"
    canonical_headers = f"content-type:{content_type}\nhost:{TENCENT_HOST}\n"
    signed_headers = "content-type;host"
    hashed_payload = hashlib.sha256(body.encode("utf-8")).hexdigest()
    canonical_request = (
        "POST\n/\n\n"
        + canonical_headers
        + "\n"
        + signed_headers
        + "\n"
        + hashed_payload
    )
    credential_scope = f"{date}/{TENCENT_SERVICE}/tc3_request"
    string_to_sign = (
        "TC3-HMAC-SHA256\n"
        + f"{timestamp}\n"
        + credential_scope
        + "\n"
        + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    )

    def _hmac(key: bytes, message: str) -> bytes:
        return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()

    secret_date = _hmac(("TC3" + secret_key).encode("utf-8"), date)
    secret_service = _hmac(secret_date, TENCENT_SERVICE)
    secret_signing = _hmac(secret_service, "tc3_request")
    signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    authorization = (
        "TC3-HMAC-SHA256 "
        f"Credential={secret_id}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )
    return {
        "Authorization": authorization,
        "Content-Type": content_type,
        "Host": TENCENT_HOST,
        "X-TC-Action": action,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Version": TENCENT_VERSION,
        "X-TC-Language": "zh-CN",
    }


def call_tencent(site: dict, action: str, payload: dict, proxy: str | None) -> dict:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    timestamp = int(datetime.now(timezone.utc).timestamp())
    headers = _tc3_headers(site["access_key"].strip(), site["secret_key"].strip(), action, body, timestamp)
    response = request(
        "POST",
        f"https://{TENCENT_HOST}/",
        proxy=proxy,
        content=body.encode("utf-8"),
        headers=headers,
    )
    try:
        data = response.json()
    except json.JSONDecodeError as exc:
        raise DnsError("腾讯云 DNS 返回了无法解析的内容。", response.text[:300]) from exc
    result = data.get("Response") or {}
    error = result.get("Error")
    if error:
        detail = f"{error.get('Code')}: {error.get('Message', '')}"
        raise DnsError(detail, detail)
    if response.status_code >= 400:
        raise DnsError(f"腾讯云 DNS HTTP {response.status_code}", response.text[:300])
    return result


def call_token(site: dict, action: str, payload: dict, proxy: str | None) -> dict:
    form = {
        "login_token": f"{site['access_key'].strip()},{site['secret_key'].strip()}",
        "format": "json",
        "error_on_empty": "no",
    }
    form.update({key: value for key, value in payload.items() if value is not None})
    body = urlencode(form)
    response = request(
        "POST",
        f"{TOKEN_ENDPOINT}/{action}",
        proxy=proxy,
        content=body.encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        data = response.json()
    except json.JSONDecodeError as exc:
        raise DnsError("DNSPod 返回了无法解析的内容。", response.text[:300]) from exc
    status = data.get("status") or {}
    code = str(status.get("code", ""))
    if code not in {"1", "0"}:
        detail = f"{code}: {status.get('message', '')}"
        raise DnsError(detail, detail)
    return data


def probe(site: dict, proxy: str | None) -> None:
    if site["provider"] == "tencent":
        call_tencent(site, "DescribeDomainList", {"Offset": 0, "Limit": 1}, proxy)
        return
    call_token(site, "Domain.List", {"offset": 0, "length": 1}, proxy)


def list_zones(site: dict, proxy: str | None) -> list[dict]:
    if site["provider"] == "tencent":
        return _tencent_zones(site, proxy)
    return _token_zones(site, proxy)


def list_records(site: dict, domain: str, proxy: str | None) -> list[dict]:
    if site["provider"] == "tencent":
        return _tencent_records(site, domain, proxy)
    return _token_records(site, domain, proxy)


def add_record(site: dict, domain: str, record: dict, proxy: str | None) -> None:
    if site["provider"] == "tencent":
        call_tencent(site, "CreateRecord", _tencent_record_body(domain, record), proxy)
        return
    call_token(site, "Record.Create", _token_record_body(domain, record), proxy)


def update_record(site: dict, domain: str, record: dict, proxy: str | None) -> None:
    if site["provider"] == "tencent":
        body = _tencent_record_body(domain, record)
        body["RecordId"] = int(record["id"])
        call_tencent(site, "ModifyRecord", body, proxy)
        return
    body = _token_record_body(domain, record)
    body["record_id"] = record["id"]
    call_token(site, "Record.Modify", body, proxy)


def set_record_status(site: dict, domain: str, record_id: str, enabled: bool, proxy: str | None) -> None:
    if site["provider"] == "tencent":
        call_tencent(
            site,
            "ModifyRecordStatus",
            {
                "Domain": domain,
                "RecordId": int(record_id),
                "Status": "ENABLE" if enabled else "DISABLE",
            },
            proxy,
        )
        return
    call_token(
        site,
        "Record.Status",
        {"domain": domain, "record_id": record_id, "status": "enable" if enabled else "disable"},
        proxy,
    )


def delete_record(site: dict, domain: str, record_id: str, proxy: str | None) -> None:
    if site["provider"] == "tencent":
        call_tencent(site, "DeleteRecord", {"Domain": domain, "RecordId": int(record_id)}, proxy)
        return
    call_token(site, "Record.Remove", {"domain": domain, "record_id": record_id}, proxy)


def _tencent_zones(site: dict, proxy: str | None) -> list[dict]:
    zones = []
    offset = 0
    while True:
        payload = call_tencent(site, "DescribeDomainList", {"Offset": offset, "Limit": 100}, proxy)
        batch = payload.get("DomainList") or []
        for item in batch:
            zones.append(
                {
                    "domain": item.get("Name") or "",
                    "record_count": int(item.get("RecordCount") or 0),
                    "dns_servers": "",
                }
            )
        info = payload.get("DomainCountInfo") or {}
        total = int(info.get("DomainTotal") or len(zones))
        offset += len(batch)
        if not batch or offset >= total:
            break
    return [zone for zone in zones if zone["domain"]]


def _tencent_records(site: dict, domain: str, proxy: str | None) -> list[dict]:
    records = []
    offset = 0
    while True:
        payload = call_tencent(
            site,
            "DescribeRecordList",
            {"Domain": domain, "Offset": offset, "Limit": 100},
            proxy,
        )
        batch = payload.get("RecordList") or []
        for item in batch:
            priority = item.get("MX")
            records.append(
                {
                    "id": str(item.get("RecordId") or ""),
                    "host": item.get("Name") or "",
                    "type": item.get("Type") or "",
                    "value": item.get("Value") or "",
                    "ttl": int(item.get("TTL") or 600),
                    "line": item.get("Line") or "默认",
                    "priority": int(priority) if priority not in (None, "") else None,
                    "status": item.get("Status") or "",
                    "created_at": "",
                    "updated_at": item.get("UpdatedOn") or "",
                    "remark": item.get("Remark") or "",
                }
            )
        info = payload.get("RecordCountInfo") or {}
        total = int(info.get("TotalCount") or len(records))
        offset += len(batch)
        if not batch or offset >= total:
            break
    return records


def _tencent_record_body(domain: str, record: dict) -> dict:
    body = {
        "Domain": domain,
        "SubDomain": record["host"],
        "RecordType": record["type"],
        "RecordLine": record["line"] or "默认",
        "Value": record["value"],
        "TTL": int(record["ttl"]),
    }
    if record.get("priority") is not None:
        body["MX"] = int(record["priority"])
    body["Remark"] = record.get("remark") or ""
    return body


def _token_zones(site: dict, proxy: str | None) -> list[dict]:
    zones = []
    offset = 0
    while True:
        payload = call_token(site, "Domain.List", {"offset": offset, "length": 100}, proxy)
        info = payload.get("info") or {}
        batch = payload.get("domains") or []
        for item in batch:
            name = item.get("name") or item.get("punycode") or ""
            zones.append(
                {
                    "domain": name,
                    "record_count": int(item.get("records") or item.get("record_count") or 0),
                    "dns_servers": "",
                }
            )
        total = int(info.get("domain_total") or info.get("all_total") or len(zones))
        offset += len(batch)
        if not batch or offset >= total:
            break
    return [zone for zone in zones if zone["domain"]]


def _token_records(site: dict, domain: str, proxy: str | None) -> list[dict]:
    records = []
    offset = 0
    while True:
        payload = call_token(
            site,
            "Record.List",
            {"domain": domain, "offset": offset, "length": 100},
            proxy,
        )
        info = payload.get("info") or {}
        batch = payload.get("records") or []
        for item in batch:
            mx = item.get("mx")
            records.append(
                {
                    "id": str(item.get("id") or ""),
                    "host": item.get("name") or "",
                    "type": item.get("type") or "",
                    "value": item.get("value") or "",
                    "ttl": int(item.get("ttl") or 600),
                    "line": item.get("line") or "默认",
                    "priority": int(mx) if mx not in (None, "") else None,
                    "status": item.get("status") or "",
                    "created_at": item.get("created_on") or "",
                    "updated_at": item.get("updated_on") or "",
                    "remark": item.get("remark") or "",
                }
            )
        total = int(info.get("record_total") or info.get("all_total") or len(records))
        offset += len(batch)
        if not batch or offset >= total:
            break
    return records


def _token_record_body(domain: str, record: dict) -> dict:
    body = {
        "domain": domain,
        "sub_domain": record["host"],
        "record_type": record["type"],
        "record_line": record["line"] or "默认",
        "value": record["value"],
        "ttl": record["ttl"],
    }
    if record.get("priority") is not None:
        body["mx"] = record["priority"]
    return body
