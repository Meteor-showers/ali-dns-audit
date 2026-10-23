from __future__ import annotations

import re

import httpx

from app.dns.errors import DnsError

PROXY_RE = re.compile(r"^(https?|socks5h?)://\S+$")


def normalize_proxy(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if not PROXY_RE.match(value):
        raise ValueError("代理要以 http://、https://、socks5:// 或 socks5h:// 开头")
    return value


def effective_proxy(site: dict, global_proxy: str) -> str | None:
    chosen = (site.get("proxy") or "").strip() or (global_proxy or "").strip()
    return chosen or None


def request(method: str, url: str, proxy: str | None = None, **kwargs) -> httpx.Response:
    try:
        with httpx.Client(proxy=proxy or None, timeout=30.0) as client:
            return client.request(method, url, **kwargs)
    except httpx.ProxyError as exc:
        raise DnsError("代理连接失败，请检查代理地址。", str(exc)) from exc
    except httpx.ConnectError as exc:
        raise DnsError(f"连接失败：{exc}", str(exc)) from exc
    except httpx.TimeoutException as exc:
        raise DnsError("连接 DNS 服务超时。", str(exc)) from exc
