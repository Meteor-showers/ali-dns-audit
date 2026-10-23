from __future__ import annotations

import re
import shutil
import subprocess

ALI_SUFFIXES = ("alidns.com", "hichina.com")
PROVIDER_RULES = (
    (("alidns.com", "hichina.com"), "阿里云DNS"),
    (("dnspod.net", "dnspod.com"), "DNSPod"),
    (("cloudflare.com",), "Cloudflare"),
    (("awsdns",), "AWS Route53"),
    (("domaincontrol.com",), "GoDaddy"),
    (("huaweicloud", "hwclouds-dns"), "华为云DNS"),
    (("myhostadmin.net",), "西部数码"),
    (("xincache.com", "xinnetdns", "xinnet.com"), "新网"),
    (("dns.com",), "DNS.COM"),
    (("zndns.com",), "中资源"),
    (("azure-dns",), "Azure DNS"),
    (("googledomains.com",), "Google"),
    (("he.net",), "Hurricane Electric"),
    (("registrar-servers.com",), "Namecheap"),
    (("ultradns",), "UltraDNS"),
    (("dnsimple.com",), "DNSimple"),
)
DNSPOD_RE = re.compile(r"(^|\.)dnsv\d*\.com$")


def is_ali(host: str) -> bool:
    return any(host == suffix or host.endswith("." + suffix) for suffix in ALI_SUFFIXES)


def is_dnspod(host: str) -> bool:
    return host.endswith("dnspod.net") or host.endswith("dnspod.com") or bool(DNSPOD_RE.search(host))


def is_wix(host: str) -> bool:
    return host == "wixdns.net" or host.endswith(".wixdns.net")


def provider_of(hosts: list[str]) -> str:
    names = []
    for host in hosts:
        matched = "其他"
        if is_wix(host):
            matched = "Wix"
        elif is_dnspod(host):
            matched = "DNSPod"
        else:
            for suffixes, name in PROVIDER_RULES:
                if any(suffix in host for suffix in suffixes):
                    matched = name
                    break
        if matched not in names:
            names.append(matched)
    return " / ".join(names)


def query_name(domain: str) -> str:
    name = domain.strip().rstrip(".").lower()
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return name + "."


def _parse_ns(output: str) -> tuple[str, list[str]]:
    statuses = re.findall(r"status:\s*([A-Z]+)", output)
    status = statuses[-1] if statuses else ""
    hosts = []
    in_answer = False
    for line in output.splitlines():
        if line.startswith(";; ANSWER SECTION"):
            in_answer = True
            continue
        if in_answer and (not line.strip() or line.startswith(";;")):
            break
        if not in_answer:
            continue
        parts = line.split()
        if len(parts) < 5 or parts[3] != "NS":
            continue
        host = parts[-1].strip().rstrip(".").lower()
        if host and not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
            hosts.append(host)
    return status, list(dict.fromkeys(hosts))


def query_ns(domain: str) -> tuple[str, list[str]]:
    dig = shutil.which("dig")
    if not dig:
        return "nodig", []
    name = query_name(domain)
    nxdomain = 0
    answered = 0
    for server in ("223.5.5.5", "119.29.29.29", "8.8.8.8"):
        try:
            proc = subprocess.run(
                [dig, "+nosearch", "+time=2", "+tries=1", f"@{server}", "NS", name],
                capture_output=True,
                text=True,
                timeout=8,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue
        status, hosts = _parse_ns(proc.stdout)
        if hosts:
            return "ok", hosts
        if status:
            answered += 1
        if status == "NXDOMAIN":
            nxdomain += 1
    if answered and nxdomain == answered:
        return "nxdomain", []
    return "fail", []


def classify(provider: str, status: str, hosts: list[str]) -> dict:
    actual = provider_of(hosts)
    if status == "nodig":
        return {"location": "NS查询失败", "provider": "", "note": "本机没有 dig，无法判断公网 NS。", "servers": []}
    if status == "nxdomain":
        return {
            "location": "公网未委托",
            "provider": "",
            "note": "账号里有这个域名，公网还查不到 NS。一般是注册商还没把 DNS 指过来。",
            "servers": [],
        }
    if status != "ok" or not hosts:
        return {"location": "NS查询失败", "provider": "", "note": "没有查到公网 NS。", "servers": hosts}
    if provider == "aliyun":
        family = "aliyun"
    elif provider == "wix":
        family = "wix"
    else:
        family = "dnspod"
    flags = [
        is_ali(host) if family == "aliyun" else is_wix(host) if family == "wix" else is_dnspod(host)
        for host in hosts
    ]
    if all(flags):
        location = {"aliyun": "阿里DNS", "wix": "Wix", "dnspod": "DNSPod"}[family]
        return {"location": location, "provider": actual, "note": "", "servers": hosts}
    note = "部分 NS 指向当前服务商。" if any(flags) else ""
    return {"location": "解析在外站", "provider": actual, "note": note, "servers": hosts}
