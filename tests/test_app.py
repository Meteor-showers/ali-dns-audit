import os
import re
import tempfile

os.environ["DNS_DATA_DIR"] = tempfile.mkdtemp(prefix="dns-console-")
os.environ["DNS_AUTO_SYNC"] = "0"

from fastapi.testclient import TestClient

from app.dns.nscheck import classify, query_name
from app.dns.service import live_zone, match_zones, normalize_query, record_enabled, relative_host
from app.main import app


def csrf_from(response) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', response.text)
    assert match, response.text
    return match.group(1)


def test_client_ip_trusts_forwarded_header_only_behind_a_private_proxy():
    from app.main import client_ip

    class Client:
        def __init__(self, host):
            self.host = host

    class Request:
        def __init__(self, host, forwarded=""):
            self.client = Client(host)
            self.headers = {"x-forwarded-for": forwarded}

    assert client_ip(Request("8.8.8.8", "1.2.3.4")) == "8.8.8.8"
    assert client_ip(Request("127.0.0.1", "203.0.113.8, 10.0.0.1")) == "203.0.113.8"
    assert client_ip(Request("10.1.2.3", "203.0.113.9")) == "203.0.113.9"
    assert client_ip(Request("::ffff:192.168.1.1", "2001:db8::1")) == "2001:db8::1"


def test_auth_error_wording():
    from app.dns.service import credential_hint, explain_auth_error

    assert "DNSPod Token" in credential_hint("tencent", "306000")
    assert credential_hint("aliyun", "LTAIexample") == ""
    assert "代理" in explain_auth_error("aliyun", "LTAIexample", "AccessPolicyDenied: ip denied")
    assert "SecretId 不存在" in explain_auth_error("tencent", "AKIDexample", "AuthFailure.SecretIdNotFound: The SecretId is not found")


def test_normalize_and_match():
    assert normalize_query("https://WWW.Example.com:443/a") == "www.example.com"
    zones = [
        {"domain": "example.com", "site_id": 1},
        {"domain": "www.example.com", "site_id": 2},
        {"domain": "other.com", "site_id": 3},
    ]
    matched = match_zones("a.www.example.com", zones)
    assert [item["site_id"] for item in matched] == [2]
    assert relative_host("www.example.com", "example.com") == "www"
    assert relative_host("example.com", "example.com") == "@"


def test_classify_external_ns():
    ali = classify("aliyun", "ok", ["ns7.alidns.com", "ns8.alidns.com"])
    assert ali["location"] == "阿里DNS"
    outside = classify("aliyun", "ok", ["ns1.dnspod.net", "ns2.dnspod.net"])
    assert outside["location"] == "解析在外站"
    assert outside["provider"] == "DNSPod"
    pod = classify("dnspod", "ok", ["a.dnspod.net"])
    assert pod["location"] == "DNSPod"
    missing = classify("aliyun", "nxdomain", [])
    assert missing["location"] == "公网未委托"
    assert query_name("思享时光.com") == "思享时光.com".encode("idna").decode("ascii") + "."


def test_live_zone_opens_the_platform_that_matches_public_ns():
    source = {
        "site_id": 1,
        "site_name": "秀色",
        "provider": "aliyun",
        "domain": "imeeta.com",
        "ns_location": "解析在外站",
        "ns_provider": "DNSPod",
    }
    same = {"site_id": 2, "site_name": "秀色", "provider": "dnspod", "domain": "imeeta.com"}
    other = {"site_id": 3, "site_name": "别的", "provider": "tencent", "domain": "imeeta.com"}
    assert live_zone(source, [source, other, same])["site_id"] == 2
    assert live_zone(same, [source, same]) is None
    assert live_zone({**source, "ns_location": ""}, [same]) is None
    from app.dns.service import choose_zone

    pod = {**same, "ns_location": "DNSPod", "ns_provider": "DNSPod"}
    assert choose_zone([source, pod])["site_id"] == 2
    assert choose_zone([source, pod, other])["site_id"] == 2


def test_page_window_keeps_ends_and_nearby_pages():
    from app.main import page_window

    assert page_window(2, 2) == [1, 2]
    assert page_window(1, 8) == [1, 2, 3, None, 8]
    assert page_window(6, 12) == [1, None, 4, 5, 6, 7, 8, None, 12]


def test_record_stamp_accepts_milliseconds_and_text():
    from datetime import datetime, timezone

    from app.db import record_stamp
    from app.log import SHANGHAI

    shanghai = datetime.fromtimestamp(1666501957, SHANGHAI).strftime("%Y-%m-%d %H:%M:%S")
    utc = datetime.fromtimestamp(1666501957, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    assert record_stamp(1666501957000) == shanghai
    assert shanghai != utc
    assert record_stamp("2024-01-02T03:04:05Z") == "2024-01-02 11:04:05"
    assert record_stamp("2021-03-28 11:27:09") == "2021-03-28 11:27:09"
    assert record_stamp("") == ""


def test_record_status_words():
    assert record_enabled("ENABLE")
    assert record_enabled("enable")
    assert record_enabled("1")
    assert not record_enabled("DISABLE")
    assert not record_enabled("disable")
    assert not record_enabled("0")


def test_refresh_stays_quiet_until_data_is_old_and_edits_win():
    from app.dns.scheduler import is_fresh, ns_due, records_due, site_due
    from app.dns.service import invalidate_zone, revision

    assert is_fresh("") is False
    assert records_due({"records_error": "失败", "records_synced_at": ""}) is False
    assert records_due({"records_error": "", "records_synced_at": ""}) is True
    from app.dns.scheduler import Scheduler

    scheduler = Scheduler()
    scheduler._cycle = True
    assert scheduler.busy_zone(1, "example.com") is False
    assert ns_due({"ns_checked_at": ""}) is True
    from app.db import clock

    recent = clock().isoformat(timespec="seconds")
    assert site_due({"last_error": "失败", "last_sync_at": recent}) is False
    invalidate_zone(7, "A.com")
    seen = revision(7, "a.com")
    invalidate_zone(7, "a.com")
    assert revision(7, "a.com") != seen


def test_legacy_password_upgrades_to_a_username():
    from app import auth, db

    previous = os.environ["DNS_DATA_DIR"]
    os.environ["DNS_DATA_DIR"] = tempfile.mkdtemp(prefix="dns-legacy-")
    try:
        salt, digest = auth.hash_password("secret1")
        db.set_setting("password_salt", salt)
        db.set_setting("password_hash", digest)
        with TestClient(app) as client:
            page = client.get("/setup")
            assert "当前密码" in page.text
            created = client.post(
                "/setup",
                data={"csrf": csrf_from(page), "username": "星", "password": "secret1"},
                follow_redirects=False,
            )
            assert created.status_code == 303
            assert db.get_setting("password_hash") == ""
            home = client.get("/")
            assert "星" in home.text
            client.post("/logout", data={"csrf": csrf_from(home)}, follow_redirects=False)
            ok = client.post(
                "/login",
                data={"csrf": csrf_from(client.get("/login")), "username": "星", "password": "secret1"},
                follow_redirects=False,
            )
            assert ok.status_code == 303
    finally:
        os.environ["DNS_DATA_DIR"] = previous


def test_setup_login_and_site_flow():
    client = TestClient(app)
    setup = client.get("/setup")
    assert setup.status_code == 200
    token = csrf_from(setup)
    created = client.post(
        "/setup",
        data={"csrf": token, "username": "ops", "password": "secret1", "confirm": "secret1"},
        follow_redirects=False,
    )
    assert created.status_code == 303
    home = client.get("/")
    assert "查询域名" in home.text

    new_page = client.get("/sites/new")
    saved = client.post(
        "/sites",
        data={
            "csrf": csrf_from(new_page),
            "name": "示意站",
            "provider": "aliyun",
            "access_key": "LTAIexample",
            "secret_key": "secret-value",
            "proxy": "",
            "remark": "",
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303
    assert saved.headers["location"].endswith("/domains")
    audit = client.get("/audit")
    assert ">添加平台<" in audit.text
    assert "示意站" in audit.text
    assert "/domains" in audit.text
    assert "secret-value" not in audit.text
    assert "ops" in audit.text
    assert "testclient" in audit.text

    from app import db

    site = db.list_sites()[0]
    edited = client.post(
        f"/sites/{site['id']}",
        data={
            "csrf": csrf_from(client.get(f"/sites/{site['id']}/edit")),
            "name": "示意站",
            "provider": "aliyun",
            "access_key": "LTAIexample",
            "secret_key": "",
            "proxy": "",
            "remark": "",
        },
        follow_redirects=False,
    )
    assert edited.status_code == 303
    assert db.get_site(site["id"])["secret_key"] == "secret-value"
    db.replace_zones(site["id"], [{"domain": "example.com", "record_count": 2, "dns_servers": "ns1.alidns.com"}])
    found = client.get("/search", params={"q": "https://www.example.com/path"}, follow_redirects=False)
    assert found.status_code == 303
    assert "domain=example.com" in found.headers["location"]
    assert "q=www.example.com" in found.headers["location"]
    assert "rq=www" in found.headers["location"]

    cached = []
    for index in range(1, 26):
        item = {
            "id": f"id-{index}",
            "host": f"h{index:02d}",
            "type": "A",
            "value": f"1.1.1.{index}",
            "ttl": 600,
            "line": "default",
            "priority": None,
            "status": "ENABLE",
        }
        if index == 21:
            item["created_at"] = "2024-01-02 03:04:05"
            item["updated_at"] = "2024-06-07 08:09:10"
            item["remark"] = "机房入口"
        cached.append(item)
    db.replace_records(site["id"], "example.com", cached)
    second = client.get("/zone", params={"site_id": site["id"], "domain": "example.com", "page": 2})
    assert second.status_code == 200
    assert "第 2 / 2 页" in second.text
    assert "h21" in second.text
    assert "h01" not in second.text
    assert "2024-01-02 03:04:05" in second.text
    assert "2024-06-07 08:09:10" in second.text
    assert "机房入口" in second.text
    assert 'class="copy"' in second.text
    assert 'data-copy="1.1.1.21"' in second.text
    assert 'class="row-edit"' in second.text
    assert 'aria-label="查询下一个域名"' in second.text
    assert 'role="switch"' in second.text
    assert "公网 NS" not in client.get(f"/sites/{site['id']}/domains").text
    wider = client.get("/zone", params={"site_id": site["id"], "domain": "example.com", "size": 50})
    assert "h01" in wider.text
    assert "h21" in wider.text
    assert "50 条" in wider.text
    kept = client.get("/zone", params={"site_id": site["id"], "domain": "example.com"})
    assert "h01" in kept.text
    filtered = client.get("/zone", params={"site_id": site["id"], "domain": "example.com", "rq": "h03"})
    assert "h03" in filtered.text
    assert "h04" not in filtered.text
    assert "读取解析记录失败" not in filtered.text
    assert "本地缓存" not in second.text
    assert "正在更新" not in second.text

    pod_id = db.create_site({
        "name": "秀色",
        "provider": "dnspod",
        "access_key": "306000",
        "secret_key": "token-value",
    })
    db.replace_zones(site["id"], [
        {"domain": "example.com", "record_count": 2, "dns_servers": "ns1.alidns.com"},
        {"domain": "imeeta.com", "record_count": 1, "dns_servers": "ns1.alidns.com"},
    ])
    db.replace_records(site["id"], "example.com", cached)
    db.replace_zones(pod_id, [{"domain": "imeeta.com", "record_count": 1, "dns_servers": "a.dnspod.net"}])
    db.replace_records(pod_id, "imeeta.com", [{
        "id": "pod-1",
        "host": "www",
        "type": "A",
        "value": "9.9.9.9",
        "ttl": 600,
        "line": "默认",
        "priority": None,
        "status": "ENABLE",
    }])
    db.update_zone_ns(site["id"], "imeeta.com", "a.dnspod.net", "解析在外站", "DNSPod")
    found_host = client.get("/search", params={"q": "qfc.imeeta.com"}, follow_redirects=False)
    assert found_host.status_code == 303
    assert f"site_id={pod_id}" in found_host.headers["location"]
    assert "rq=qfc" in found_host.headers["location"]
    jumped = client.get("/zone", params={"site_id": site["id"], "domain": "imeeta.com"}, follow_redirects=False)
    assert jumped.status_code == 303
    assert f"site_id={pod_id}" in jumped.headers["location"]
    opened = client.get(jumped.headers["location"])
    assert "9.9.9.9" in opened.text
    listing = client.get(f"/sites/{site['id']}/domains")
    assert "imeeta.com" not in listing.text
    assert "1 个解析在外站" in listing.text
    everything = client.get(f"/sites/{site['id']}/domains", params={"loc": "all"})
    assert "解析在「秀色」DNSPod Token" in everything.text
    assert "平台" in client.get("/sites").text
    board = client.get("/")
    assert "示意站" in board.text
    assert "imeeta.com" in board.text
    assert "secret-value" not in board.text
    assert "token-value" not in board.text

    settings = client.get("/settings")
    assert "ops" in settings.text
    added = client.post(
        "/settings/users",
        data={
            "csrf": csrf_from(settings),
            "username": "other",
            "password": "secret2",
            "confirm": "secret2",
        },
        follow_redirects=False,
    )
    assert added.status_code == 303
    listed = client.get("/settings")
    assert "other" in listed.text
    assert "管理" in listed.text
    from app import db as app_db

    admin = app_db.list_users()[0]
    assert admin["username"] == "ops"
    client.post("/logout", data={"csrf": csrf_from(listed)}, follow_redirects=False)
    other_login = client.post(
        "/login",
        data={"csrf": csrf_from(client.get("/login")), "username": "other", "password": "secret2"},
        follow_redirects=False,
    )
    assert other_login.status_code == 303
    other_settings = client.get("/settings")
    assert f"/settings/users/{admin['id']}/delete" not in other_settings.text
    blocked_admin = client.post(
        f"/settings/users/{admin['id']}/delete",
        data={"csrf": csrf_from(other_settings)},
        follow_redirects=False,
    )
    assert blocked_admin.status_code == 303
    assert app_db.get_user(admin["id"])["username"] == "ops"
    client.post("/logout", data={"csrf": csrf_from(client.get("/"))}, follow_redirects=False)
    client.post(
        "/login",
        data={"csrf": csrf_from(client.get("/login")), "username": "ops", "password": "secret1"},
        follow_redirects=False,
    )
    rejected = client.post(
        "/settings/proxy",
        data={"csrf": csrf_from(client.get("/settings")), "global_proxy": "127.0.0.1:1080"},
    )
    assert rejected.status_code == 400

    client.post("/logout", data={"csrf": csrf_from(client.get("/sites"))}, follow_redirects=False)
    guest_home = client.get("/", follow_redirects=False)
    assert guest_home.status_code == 200
    assert "查询域名" in guest_home.text
    assert 'aria-label="展开侧边栏"' in guest_home.text
    assert "示意站" not in guest_home.text
    assert "imeeta.com" not in guest_home.text
    assert "需要留意" not in guest_home.text
    assert "最近操作" not in guest_home.text
    assert "管理平台" not in guest_home.text
    assert 'href="/settings"' not in guest_home.text
    guest_zone = client.get("/zone", params={"site_id": site["id"], "domain": "example.com"})
    assert guest_zone.status_code == 200
    assert "h01" in guest_zone.text
    assert "添加解析" not in guest_zone.text
    assert 'class="row-edit"' not in guest_zone.text
    assert 'role="switch"' not in guest_zone.text
    assert f"/sites/{site['id']}/domains" not in guest_zone.text
    guest_from_search = client.get(
        "/zone",
        params={"site_id": site["id"], "domain": "example.com", "q": "www.example.com", "rq": "www"},
    )
    assert f"/sites/{site['id']}/domains" not in guest_from_search.text
    assert 'href="/search?q=www.example.com&stay=1"' in guest_from_search.text
    cleared = client.get("/zone", params={"site_id": site["id"], "domain": "example.com", "q": "www.example.com"})
    assert 'value="www"' in cleared.text
    assert "h01" not in cleared.text
    assert "h21" not in cleared.text
    assert ">清除</a>" not in cleared.text
    guest_list = client.get("/search", params={"q": "www.example.com", "stay": "1"})
    assert guest_list.status_code == 200
    assert "example.com" in guest_list.text
    assert "imeeta.com" not in guest_list.text
    guest_miss = client.get("/search", params={"q": "not-here.test", "stay": "1"})
    assert "没有找到" in guest_miss.text
    assert "imeeta.com" not in guest_miss.text
    assert "示意站" not in guest_miss.text
    guest_domains = client.get(f"/sites/{site['id']}/domains", follow_redirects=False)
    assert guest_domains.status_code == 303
    assert guest_domains.headers["location"] == "/login"
    for blocked_path in ("/settings", "/audit", "/sites", "/sites/new", "/zone/record"):
        blocked = client.get(blocked_path, follow_redirects=False)
        assert blocked.status_code == 303
        assert blocked.headers["location"] == "/login"
    denied_write = client.post(
        "/zone/record/delete",
        data={"csrf": "nope", "site_id": site["id"], "domain": "example.com", "record_id": "id-1"},
        follow_redirects=False,
    )
    assert denied_write.status_code == 303
    assert denied_write.headers["location"] == "/login"
    login = client.get("/login")
    assert "用户名" in login.text
    denied = client.post(
        "/login",
        data={"csrf": csrf_from(login), "username": "ops", "password": "wrong"},
        follow_redirects=False,
    )
    assert denied.status_code == 400
    ok = client.post(
        "/login",
        data={"csrf": csrf_from(client.get("/login")), "username": "ops", "password": "secret1"},
        follow_redirects=False,
    )
    assert ok.status_code == 303
    rejected_key = client.post(
        "/sites",
        data={
            "csrf": csrf_from(client.get("/sites/new")),
            "name": "错类型",
            "provider": "tencent",
            "access_key": "306000",
            "secret_key": "token-value",
            "proxy": "",
            "remark": "",
        },
    )
    assert rejected_key.status_code == 400
    assert "DNSPod Token" in rejected_key.text
    assert all(item["name"] != "错类型" for item in db.list_sites())
    again = client.get("/audit")
    assert ">登录<" in again.text
    assert ">登录失败<" in again.text


def test_log_time_is_shanghai_wall_clock():
    import logging
    from datetime import datetime, timezone

    from app.log import DATE_FORMAT, ShanghaiFormatter, log_path

    record = logging.LogRecord("app", logging.INFO, __file__, 1, "hello", (), None)
    record.created = datetime(2026, 10, 23, 2, 33, 5, tzinfo=timezone.utc).timestamp()
    line = ShanghaiFormatter("%(asctime)s %(message)s", DATE_FORMAT).format(record)
    assert line == "2026-10-23 10:33:05 hello"
    from app.db import clock, now

    utc = datetime.now(timezone.utc).replace(tzinfo=None)
    assert abs((clock() - utc).total_seconds() - 8 * 3600) < 2
    assert now() == clock().isoformat(timespec="seconds")
    logging.getLogger("app").info("shanghai-mark")
    text = log_path().read_text(encoding="utf-8")
    assert "shanghai-mark" in text
    assert "INFO app " in text


def test_wix_updates_one_value_and_hides_status_switch():
    from app.dns.errors import DnsError
    from app.dns.service import credential_hint, live_zone, parse_record, record_types_for
    from app.dns.wix import decode_id, flatten_records, plan_change, set_record_status

    raw = [
        {"type": "A", "hostName": "example.com", "ttl": 3600, "values": ["1.2.3.4", "5.6.7.8"]},
        {"type": "MX", "hostName": "example.com", "ttl": 3600, "values": ["10 aspmx.l.google.com"]},
        {"type": "CNAME", "hostName": "www.example.com", "ttl": 600, "values": ["example.com"]},
    ]
    rows = flatten_records("example.com", raw)
    assert [row["host"] for row in rows] == ["@", "@", "@", "www"]
    assert rows[2]["priority"] == 10
    assert rows[2]["value"] == "aspmx.l.google.com"
    assert decode_id(rows[2]["id"])["priority"] == 10
    changed = plan_change(
        "example.com",
        raw,
        "update",
        {"type": "A", "host": "@", "value": "9.9.9.9", "ttl": 300, "priority": None},
        decode_id(rows[0]["id"]),
    )
    assert changed["deletions"][0]["values"] == ["1.2.3.4", "5.6.7.8"]
    assert changed["additions"][0]["values"] == ["9.9.9.9", "5.6.7.8"]
    assert changed["additions"][0]["ttl"] == 300
    removed = plan_change("example.com", raw, "delete", rows[0], decode_id(rows[0]["id"]))
    assert removed["additions"][0]["values"] == ["5.6.7.8"]
    try:
        plan_change(
            "example.com",
            raw,
            "add",
            {"type": "CNAME", "host": "@", "value": "a.example.net", "ttl": 600, "priority": None},
        )
    except DnsError as exc:
        assert "CNAME" in exc.message
    else:
        raise AssertionError("根域名 CNAME 应该被拒绝")
    try:
        plan_change(
            "example.com",
            raw,
            "add",
            {"type": "A", "host": "@", "value": "1.2.3.4", "ttl": 600, "priority": None},
        )
    except DnsError as exc:
        assert "已经存在" in exc.message
    else:
        raise AssertionError("重复记录应该被拒绝")
    try:
        set_record_status({}, "example.com", "x", False, None)
    except DnsError as exc:
        assert "停止" in exc.message
    else:
        raise AssertionError("Wix 没有停止")
    assert "CAA" not in record_types_for("wix")
    try:
        parse_record({"host": "@", "type": "CAA", "value": '0 issue "letsencrypt.org"', "ttl": "600"}, "wix")
    except DnsError as exc:
        assert "不支持" in exc.message
    else:
        raise AssertionError("CAA 不应该写入 Wix")
    assert "Account ID" in credential_hint("wix", "IST.example")
    wix_ns = classify("wix", "ok", ["ns0.wixdns.net", "ns1.wixdns.net"])
    assert wix_ns["location"] == "Wix"
    outside = classify("aliyun", "ok", ["ns0.wixdns.net"])
    assert outside["location"] == "解析在外站"
    assert outside["provider"] == "Wix"
    source = {
        "site_id": 1,
        "site_name": "站",
        "provider": "aliyun",
        "domain": "example.com",
        "ns_location": "解析在外站",
        "ns_provider": "Wix",
    }
    target = {
        "site_id": 2,
        "site_name": "站",
        "provider": "wix",
        "domain": "example.com",
        "ns_location": "Wix",
        "ns_provider": "Wix",
    }
    assert live_zone(source, [source, target])["site_id"] == 2
    assert flatten_records("例子.com", [{"type": "A", "hostName": "www.例子.com", "ttl": 600, "values": ["1.1.1.1"]}])[0]["host"] == "www"

    previous = os.environ["DNS_DATA_DIR"]
    os.environ["DNS_DATA_DIR"] = tempfile.mkdtemp(prefix="dns-wix-")
    try:
        from app import db

        site_id = db.create_site({"name": "计数", "provider": "wix", "access_key": "account", "secret_key": "auth"})
        db.replace_zones(site_id, [{"domain": "example.com", "record_count": 4}])
        db.replace_zones(site_id, [{"domain": "example.com"}])
        assert db.get_zone(site_id, "example.com")["record_count"] == 4
        with TestClient(app) as client:
            setup = client.get("/setup")
            client.post(
                "/setup",
                data={"csrf": csrf_from(setup), "username": "ops", "password": "secret1", "confirm": "secret1"},
                follow_redirects=False,
            )
            new_page = client.get("/sites/new")
            assert "Wix" in new_page.text
            assert "Account ID" in new_page.text
            assert "Authorization" in new_page.text
            saved = client.post(
                "/sites",
                data={
                    "csrf": csrf_from(new_page),
                    "name": "Wix站",
                    "provider": "wix",
                    "access_key": "11111111-2222-3333-4444-555555555555",
                    "secret_key": "IST.secret-value",
                    "proxy": "",
                    "remark": "",
                },
                follow_redirects=False,
            )
            assert saved.status_code == 303
            saved_site = [item for item in db.list_sites() if item["name"] == "Wix站"][0]
            assert "IST.secret-value" == saved_site["secret_key"]
            db.replace_zones(saved_site["id"], [{"domain": "example.com", "record_count": 1}])
            db.replace_records(saved_site["id"], "example.com", rows[:1])
            page = client.get("/zone", params={"site_id": saved_site["id"], "domain": "example.com"})
            assert page.status_code == 200
            assert 'role="switch"' not in page.text
            assert "启用" in page.text
            assert '<option value="CAA"' not in page.text
            assert '<option value="A"' in page.text
            assert "IST.secret-value" not in page.text
    finally:
        os.environ["DNS_DATA_DIR"] = previous


def test_godaddy_replaces_one_value_and_hides_status_switch():
    from app.dns.errors import DnsError
    from app.dns.godaddy import decode_id, flatten_records, plan_change, set_record_status, _record_path
    from app.dns.service import credential_hint, live_zone, parse_record, record_types_for

    raw = [
        {"type": "A", "name": "@", "data": "1.2.3.4", "ttl": 600},
        {"type": "A", "name": "@", "data": "5.6.7.8", "ttl": 600},
        {"type": "MX", "name": "@", "data": "aspmx.l.google.com", "ttl": 3600, "priority": 10},
        {"type": "SRV", "name": "_sip._tcp", "data": "sip.example.com", "ttl": 600, "priority": 10, "weight": 1, "port": 443},
    ]
    rows = flatten_records("example.com", raw)
    assert [row["host"] for row in rows] == ["@", "@", "@", "_sip._tcp"]
    assert rows[0]["value"] == "1.2.3.4"
    mx = next(row for row in rows if row["type"] == "MX")
    assert mx["priority"] == 10
    assert mx["value"] == "aspmx.l.google.com"
    srv = next(row for row in rows if row["type"] == "SRV")
    assert srv["value"] == "1 443 sip.example.com"
    assert decode_id(rows[0]["id"])["value"] == "1.2.3.4"
    assert flatten_records("example.com", [{"type": "A", "name": "WWW", "data": "1.1.1.1", "ttl": 600}])[0]["host"] == "www"
    assert _record_path("example.com", "A", "@").endswith("/records/A/%40")
    assert _record_path("example.com", "A", "*").endswith("/records/A/*")
    moved = plan_change(
        "example.com",
        raw[:1],
        "update",
        {"type": "A", "host": "www", "value": "1.2.3.4", "ttl": 600, "priority": None},
        decode_id(rows[0]["id"]),
    )
    assert [(item["type"], item["name"]) for item in moved] == [("A", "www"), ("A", "@")]
    assert moved[1]["records"] == []
    ns_raw = [{"type": "NS", "name": "@", "data": "ns41.domaincontrol.com", "ttl": 3600}]
    ns_row = flatten_records("example.com", ns_raw)[0]
    try:
        plan_change("example.com", ns_raw, "delete", ns_row, decode_id(ns_row["id"]))
    except DnsError as exc:
        assert "NS" in exc.message
    else:
        raise AssertionError("根域名最后一条 NS 不能删除")
    changed = plan_change(
        "example.com",
        raw,
        "update",
        {"type": "A", "host": "@", "value": "9.9.9.9", "ttl": 600, "priority": None},
        decode_id(rows[0]["id"]),
    )
    assert {row["value"] for row in changed[0]["records"]} == {"9.9.9.9", "5.6.7.8"}
    removed = plan_change("example.com", raw, "delete", rows[0], decode_id(rows[0]["id"]))
    assert [row["value"] for row in removed[0]["records"]] == ["5.6.7.8"]
    try:
        plan_change(
            "example.com",
            raw,
            "add",
            {"type": "CNAME", "host": "@", "value": "a.example.net", "ttl": 600, "priority": None},
        )
    except DnsError as exc:
        assert "CNAME" in exc.message
    else:
        raise AssertionError("根域名 CNAME 应该被拒绝")
    try:
        plan_change(
            "example.com",
            raw,
            "add",
            {"type": "A", "host": "@", "value": "1.2.3.4", "ttl": 600, "priority": None},
        )
    except DnsError as exc:
        assert "已经存在" in exc.message
    else:
        raise AssertionError("重复记录应该被拒绝")
    try:
        set_record_status({}, "example.com", "x", False, None)
    except DnsError as exc:
        assert "停止" in exc.message
    else:
        raise AssertionError("GoDaddy 没有停止")
    assert "CAA" in record_types_for("godaddy")
    assert "SPF" not in record_types_for("godaddy")
    try:
        parse_record({"host": "@", "type": "A", "value": "1.1.1.1", "ttl": "60"}, "godaddy")
    except DnsError as exc:
        assert "600" in exc.message
    else:
        raise AssertionError("GoDaddy TTL 不能小于 600")
    assert "分开填" in credential_hint("godaddy", "key:secret")
    owned = classify("godaddy", "ok", ["ns41.domaincontrol.com", "ns42.domaincontrol.com"])
    assert owned["location"] == "GoDaddy"
    outside = classify("aliyun", "ok", ["ns41.domaincontrol.com"])
    assert outside["location"] == "解析在外站"
    assert outside["provider"] == "GoDaddy"
    assert classify("godaddy", "ok", ["notdomaincontrol.com"])["location"] == "解析在外站"
    source = {
        "site_id": 1,
        "site_name": "站",
        "provider": "aliyun",
        "domain": "example.com",
        "ns_location": "解析在外站",
        "ns_provider": "GoDaddy",
    }
    target = {
        "site_id": 2,
        "site_name": "站",
        "provider": "godaddy",
        "domain": "example.com",
        "ns_location": "GoDaddy",
        "ns_provider": "GoDaddy",
    }
    assert live_zone(source, [source, target])["site_id"] == 2

    previous = os.environ["DNS_DATA_DIR"]
    os.environ["DNS_DATA_DIR"] = tempfile.mkdtemp(prefix="dns-godaddy-")
    try:
        from app import db

        with TestClient(app) as client:
            setup = client.get("/setup")
            client.post(
                "/setup",
                data={"csrf": csrf_from(setup), "username": "ops", "password": "secret1", "confirm": "secret1"},
                follow_redirects=False,
            )
            new_page = client.get("/sites/new")
            assert "GoDaddy" in new_page.text
            assert "API Key" in new_page.text
            saved = client.post(
                "/sites",
                data={
                    "csrf": csrf_from(new_page),
                    "name": "GoDaddy站",
                    "provider": "godaddy",
                    "access_key": "godaddy-key",
                    "secret_key": "godaddy-secret",
                    "proxy": "",
                    "remark": "",
                },
                follow_redirects=False,
            )
            assert saved.status_code == 303
            saved_site = [item for item in db.list_sites() if item["name"] == "GoDaddy站"][0]
            assert saved_site["secret_key"] == "godaddy-secret"
            db.replace_zones(saved_site["id"], [{"domain": "example.com", "record_count": 1}])
            db.replace_records(saved_site["id"], "example.com", rows[:1])
            page = client.get("/zone", params={"site_id": saved_site["id"], "domain": "example.com"})
            assert page.status_code == 200
            assert 'role="switch"' not in page.text
            assert "启用" in page.text
            assert '<option value="CAA"' in page.text
            assert '<option value="SPF"' not in page.text
            assert "godaddy-secret" not in page.text
    finally:
        os.environ["DNS_DATA_DIR"] = previous


def test_query_result_shows_where_the_domain_is_used(monkeypatch):
    from datetime import timedelta

    from app.dns.products import covers, domain_listed, find_usage, hints_for, oss_cnames, usage_phrase

    assert covers("wb.xiu361.cn", "wb.xiu361.cn")
    assert covers("*.xiu361.cn", "wb.xiu361.cn")
    assert not covers("*.xiu361.cn", "a.wb.xiu361.cn")
    assert hints_for("wb.xiu361.cn.w.kunlunsl.com") == {"accelerate"}
    assert hints_for("img.oss-cn-hangzhou.aliyuncs.com") == {"oss"}
    assert hints_for("alb-xxx.cn-hangzhou.alb.aliyuncsslb.com") == {"alb"}
    assert hints_for("1.2.3.4") == set()
    from app import db as usage_db
    from app.dns.products import (
        ACCELERATE,
        _account_id,
        _in_zone,
        catalogs_for,
        fingerprint,
        labels_for_name,
        load_usages,
    )

    catalog = {"全站加速": {"service.haixiutv.com"}, "CDN": {"csservice.haixiutv.com"}}
    assert labels_for_name("service.haixiutv.com", catalog) == ["全站加速"]
    assert labels_for_name("csservice.haixiutv.com", catalog) == ["CDN"]
    assert _in_zone("csservice.haixiutv.com", "haixiutv.com")
    assert _in_zone("*.haixiutv.com", "haixiutv.com")
    assert not _in_zone("nothaixiutv.com", "haixiutv.com")
    usage_db.write_usage("empty.example", "fp", "")
    usage_db.write_usage("hit.example", "fp", "在秀色的 CDN 使用")
    with usage_db.connect() as conn:
        recent = (usage_db.clock() - timedelta(minutes=30)).isoformat(timespec="seconds")
        stale_miss = (usage_db.clock() - timedelta(hours=2)).isoformat(timespec="seconds")
        conn.execute("UPDATE usage_cache SET checked_at = ? WHERE fqdn = ?", (recent, "empty.example"))
        conn.execute("UPDATE usage_cache SET checked_at = ? WHERE fqdn = ?", (stale_miss, "hit.example"))
    assert usage_db.read_usage("empty.example", "fp") == ""
    with usage_db.connect() as conn:
        conn.execute("UPDATE usage_cache SET checked_at = ? WHERE fqdn = ?", (stale_miss, "empty.example"))
    assert usage_db.read_usage("empty.example", "fp") is None
    assert usage_db.read_usage("hit.example", "fp") == "在秀色的 CDN 使用"

    def fake_call(key, secret, endpoint, version, action, extra, proxy):
        return {
            "TotalCount": 2,
            "Domains": {"PageData": [{"DomainName": "csservice.haixiutv.com"}, {"DomainName": "nothaixiutv.com"}]},
        }

    monkeypatch.setattr("app.dns.products._call", fake_call)
    from app.dns.products import _list_suffix

    label, names, state, complete = _list_suffix("k", "s", None, "haixiutv.com", ACCELERATE[0])
    assert label == "CDN"
    assert names == {"csservice.haixiutv.com"}
    assert state == "ok" and complete is True

    list_calls = {"n": 0}

    def fake_list(key, secret, proxy, zone, spec):
        list_calls["n"] += 1
        label_name = spec[0]
        if key == "bad":
            return label_name, set(), "auth", False
        if key == "deny":
            return label_name, set(), "deny", False
        if zone == "partial.example":
            return label_name, set(), "ok", False
        names = set()
        if label_name == "全站加速":
            names.add(f"service.{zone}")
        elif label_name == "CDN":
            names.add(f"csservice.{zone}")
        return label_name, names, "ok", True

    monkeypatch.setattr("app.dns.products._list_suffix", fake_list)
    show = [({"id": 3, "name": "瞬秀", "access_key": "k", "secret_key": "s"}, None)]
    many = load_usages(
        show,
        "haixiutv.com",
        [
            {"host": "service", "type": "CNAME", "value": "service.haixiutv.com.w.kunluncan.com", "status": "ENABLE"},
            {"host": "csservice", "type": "CNAME", "value": "csservice.haixiutv.com.w.cdngslb.com", "status": "ENABLE"},
            {"host": "inner-t2-service", "type": "A", "value": "192.168.84.57", "status": "ENABLE"},
        ],
    )
    assert many["service"] == "在瞬秀的 全站加速 使用"
    assert many["csservice"] == "在瞬秀的 CDN 使用"
    assert many["inner-t2-service"] == ""
    assert list_calls["n"] == 4
    other = load_usages(
        show,
        "haixiutv.com",
        [{"host": "h5service", "type": "CNAME", "value": "h5service.haixiutv.com.w.kunluncan.com", "status": "ENABLE"}],
    )
    assert other["h5service"] == ""
    assert list_calls["n"] == 4
    h5_fp = fingerprint(["h5service.haixiutv.com.w.kunluncan.com"], show)
    assert usage_db.read_usage("h5service.haixiutv.com", h5_fp) == ""
    assert load_usages(
        show,
        "haixiutv.com",
        [{"host": "service", "type": "CNAME", "value": "service.haixiutv.com.w.kunluncan.com", "status": "ENABLE"}],
    )["service"] == "在瞬秀的 全站加速 使用"
    assert list_calls["n"] == 4
    partial_rows = [
        {"host": "service", "type": "CNAME", "value": "service.partial.example.w.kunluncan.com", "status": "ENABLE"}
    ]
    assert load_usages(show, "partial.example", partial_rows)["service"] == ""
    partial_fp = fingerprint(["service.partial.example.w.kunluncan.com"], show)
    assert usage_db.read_usage("service.partial.example", partial_fp) is None
    assert load_usages(show, "partial.example", partial_rows)["service"] == ""
    assert list_calls["n"] == 8
    mixed = [
        ({"id": 11, "name": "瞬秀", "access_key": "good", "secret_key": "s"}, None),
        ({"id": 12, "name": "秀色", "access_key": "bad", "secret_key": "s"}, None),
    ]
    mixed_rows = [
        {"host": "service", "type": "CNAME", "value": "service.mix.example.w.kunluncan.com", "status": "ENABLE"}
    ]
    assert load_usages(mixed, "mix.example", mixed_rows)["service"] == "在瞬秀的 全站加速 使用"
    mixed_fp = fingerprint(["service.mix.example.w.kunluncan.com"], mixed)
    assert usage_db.read_usage("service.mix.example", mixed_fp) is None
    denied = [({"id": 13, "name": "瞬秀", "access_key": "deny", "secret_key": "s"}, None)]
    denied_rows = [
        {"host": "service", "type": "CNAME", "value": "service.deny.example.w.kunluncan.com", "status": "ENABLE"}
    ]
    assert load_usages(denied, "deny.example", denied_rows)["service"] == "没有权限"
    oss_calls = []

    def fake_oss(key, secret, proxy, value):
        oss_calls.append(value)
        return True, "ok"

    monkeypatch.setattr("app.dns.products._confirm_oss", fake_oss)
    oss_account = [({"id": 14, "name": "瞬秀", "access_key": "k", "secret_key": "s"}, None)]
    oss_found = load_usages(
        oss_account,
        "oss.example",
        [
            {"host": "img", "type": "CNAME", "value": "img.oss-cn-hangzhou.aliyuncs.com", "status": "ENABLE"},
            {"host": "img2", "type": "CNAME", "value": "img.oss-cn-hangzhou.aliyuncs.com", "status": "ENABLE"},
            {"host": "video", "type": "CNAME", "value": "video.oss-cn-hangzhou.aliyuncs.com", "status": "ENABLE"},
        ],
    )
    assert oss_found["img"] == "在瞬秀的 OSS 使用"
    assert oss_found["img2"] == "在瞬秀的 OSS 使用"
    assert oss_found["video"] == "在瞬秀的 OSS 使用"
    assert sorted(oss_calls) == ["img.oss-cn-hangzhou.aliyuncs.com", "video.oss-cn-hangzhou.aliyuncs.com"]
    import threading
    import time

    started = threading.Event()
    release = threading.Event()
    flight_calls = {"n": 0}

    def slow_list(key, secret, proxy, zone, spec):
        flight_calls["n"] += 1
        started.set()
        assert release.wait(2)
        return spec[0], set(), "ok", True

    monkeypatch.setattr("app.dns.products._list_suffix", slow_list)
    flight_accounts = [({"id": 15, "name": "飞行", "access_key": "k", "secret_key": "s"}, None)]
    flights = []

    def run_flight():
        flights.append(catalogs_for(flight_accounts, "flight.example"))

    first = threading.Thread(target=run_flight)
    first.start()
    assert started.wait(2)
    second = threading.Thread(target=run_flight)
    second.start()
    time.sleep(0.1)
    release.set()
    first.join(2)
    second.join(2)
    assert flight_calls["n"] == 4
    assert len(flights) == 2
    assert _account_id({"id": 15, "name": "飞行"}) == "15"
    assert usage_phrase([("秀色", "全站加速"), ("秀色", "CDN")]) == "在秀色的 CDN、全站加速 使用"
    assert domain_listed({"Domains": {"PageData": [{"DomainName": "wb.xiu361.cn"}]}}, "wb.xiu361.cn")
    assert oss_cnames("<ListCnameResult><Cname><Domain>wb.xiu361.cn</Domain></Cname></ListCnameResult>") == [
        "wb.xiu361.cn"
    ]
    calls = {"n": 0}

    def fake_account(site, proxy, domain, values):
        calls["n"] += 1
        return [(site["name"], "CDN")], "ok"

    monkeypatch.setattr("app.dns.products._account", fake_account)
    accounts = [({"id": 7, "name": "秀色", "access_key": "k", "secret_key": "s"}, None)]
    values = ["wb.xiu361.cn.w.kunlunsl.com"]
    assert find_usage(accounts, "wb.xiu361.cn", values) == "在秀色的 CDN 使用"
    assert find_usage(accounts, "wb.xiu361.cn", values) == "在秀色的 CDN 使用"
    assert calls["n"] == 1
    assert find_usage(accounts, "wb.xiu361.cn", ["1.2.3.4"]) == ""
    assert calls["n"] == 1
    from app import db as usage_db

    old = (usage_db.clock() - timedelta(hours=25)).isoformat(timespec="seconds")
    with usage_db.connect() as conn:
        conn.execute("UPDATE usage_cache SET checked_at = ? WHERE fqdn = ?", (old, "wb.xiu361.cn"))
    assert find_usage(accounts, "wb.xiu361.cn", values) == "在秀色的 CDN 使用"
    assert calls["n"] == 2
    seen = {}

    def fake_load(accounts, zone, records):
        seen["hosts"] = [row["host"] for row in records]
        seen["sites"] = [item[0]["name"] for item in accounts]
        return {row["host"].lower(): "在秀色的 CDN 使用" for row in records}

    monkeypatch.setattr("app.main.load_usages", fake_load)
    previous = os.environ["DNS_DATA_DIR"]
    os.environ["DNS_DATA_DIR"] = tempfile.mkdtemp(prefix="dns-usage-")
    try:
        from app import db

        with TestClient(app) as client:
            setup = client.get("/setup")
            client.post(
                "/setup",
                data={"csrf": csrf_from(setup), "username": "ops", "password": "secret1", "confirm": "secret1"},
                follow_redirects=False,
            )
            new_page = client.get("/sites/new")
            client.post(
                "/sites",
                data={
                    "csrf": csrf_from(new_page),
                    "name": "秀色",
                    "provider": "aliyun",
                    "access_key": "LTAIexample",
                    "secret_key": "secret-value",
                    "proxy": "",
                    "remark": "",
                },
                follow_redirects=False,
            )
            new_page = client.get("/sites/new")
            client.post(
                "/sites",
                data={
                    "csrf": csrf_from(new_page),
                    "name": "DNSPod站",
                    "provider": "dnspod",
                    "access_key": "10001",
                    "secret_key": "token-value",
                    "proxy": "",
                    "remark": "",
                },
                follow_redirects=False,
            )
            site = [item for item in db.list_sites() if item["name"] == "秀色"][0]
            db.replace_zones(site["id"], [{"domain": "xiu361.cn", "record_count": 1}])
            db.replace_records(
                site["id"],
                "xiu361.cn",
                [{
                    "id": "wb",
                    "host": "wb",
                    "type": "CNAME",
                    "value": "wb.xiu361.cn.w.kunlunsl.com",
                    "ttl": 600,
                    "line": "default",
                    "priority": None,
                    "status": "ENABLE",
                }],
            )
            page = client.get(
                "/zone",
                params={"site_id": site["id"], "domain": "xiu361.cn", "q": "wb.xiu361.cn", "rq": "wb"},
            )
            assert page.status_code == 200
            assert "使用位置" in page.text
            assert "正在查询" in page.text
            assert "if (!res.ok)" in page.text
            assert "wb.xiu361.cn.w.kunlunsl.com" in page.text
            assert seen == {}
            looked = client.get(
                "/zone/usage",
                params={"site_id": site["id"], "domain": "xiu361.cn", "q": "wb.xiu361.cn"},
            )
            assert looked.status_code == 200
            assert looked.json()["items"]["wb"] == "在秀色的 CDN 使用"
            assert looked.json()["phrase"] == "在秀色的 CDN 使用"
            assert seen["hosts"] == ["wb"]
            assert seen["sites"] == ["秀色"]
            assert "secret-value" not in page.text
            assert "secret-value" not in looked.text
            plain = client.get("/zone", params={"site_id": site["id"], "domain": "xiu361.cn"})
            assert "使用位置" not in plain.text
        with TestClient(app) as guest:
            guest_page = guest.get(
                "/zone",
                params={"site_id": site["id"], "domain": "xiu361.cn", "q": "wb.xiu361.cn"},
            )
            assert guest_page.status_code == 200
            assert "使用位置" in guest_page.text
            assert "正在查询" in guest_page.text
    finally:
        os.environ["DNS_DATA_DIR"] = previous


def test_ldap_keeps_admin_password_and_accepts_directory_users(monkeypatch):
    previous = os.environ["DNS_DATA_DIR"]
    os.environ["DNS_DATA_DIR"] = tempfile.mkdtemp(prefix="dns-ldap-")
    try:
        from app import db

        with TestClient(app) as client:
            setup = client.get("/setup")
            client.post(
                "/setup",
                data={"csrf": csrf_from(setup), "username": "admin", "password": "secret1", "confirm": "secret1"},
                follow_redirects=False,
            )
            settings = client.get("/settings")
            client.post(
                "/settings/users",
                data={"csrf": csrf_from(settings), "username": "local", "password": "secret2", "confirm": "secret2"},
                follow_redirects=False,
            )
            settings = client.get("/settings")
            saved = client.post(
                "/settings/ldap",
                data={
                    "csrf": csrf_from(settings),
                    "action": "save",
                    "ldap_url": "ldaps://ldap.example.com",
                    "ldap_ous": "ou=一部门,dc=example,dc=com | ou=二部门,dc=example,dc=com",
                    "ldap_bind_dn": "cn=reader,dc=example,dc=com",
                    "ldap_bind_password": "bind-secret",
                    "ldap_filter": "(sAMAccountName=%(user)s)",
                    "ldap_attr_map": '{"username": "sAMAccountName", "name": "cn", "email": "mail"}',
                    "ldap_enabled": "1",
                },
                follow_redirects=False,
            )
            assert saved.status_code == 303
            page = client.get("/settings")
            assert "bind-secret" not in page.text
            assert "已保存，留空不修改" in page.text
            assert "LDAP 已启用" not in page.text or "除了管理账号" in page.text

            def fake_verify(username, password):
                if username == "alice" and password == "dir-secret":
                    return {"username": "alice", "name": "Alice", "email": "alice@example.com"}
                return None

            monkeypatch.setattr("app.ldap_auth.verify", fake_verify)
            client.post("/logout", data={"csrf": csrf_from(page)}, follow_redirects=False)
            admin_login = client.post(
                "/login",
                data={"csrf": csrf_from(client.get("/login")), "username": "admin", "password": "secret1"},
                follow_redirects=False,
            )
            assert admin_login.status_code == 303
            client.post("/logout", data={"csrf": csrf_from(client.get("/"))}, follow_redirects=False)
            local_login = client.post(
                "/login",
                data={"csrf": csrf_from(client.get("/login")), "username": "local", "password": "secret2"},
                follow_redirects=False,
            )
            assert local_login.status_code == 400
            alice = client.post(
                "/login",
                data={"csrf": csrf_from(client.get("/login")), "username": "alice", "password": "dir-secret"},
                follow_redirects=False,
            )
            assert alice.status_code == 303
            assert db.get_user_by_name("alice")["kind"] == "ldap"
            home = client.get("/settings")
            assert "LDAP" in home.text
            assert "由 LDAP 管理" in home.text
            client.post("/logout", data={"csrf": csrf_from(home)}, follow_redirects=False)
            denied = client.post(
                "/login",
                data={"csrf": csrf_from(client.get("/login")), "username": "bob", "password": "nope"},
                follow_redirects=False,
            )
            assert denied.status_code == 400
            client.post(
                "/login",
                data={"csrf": csrf_from(client.get("/login")), "username": "admin", "password": "secret1"},
                follow_redirects=False,
            )

            def fake_collect(config, search_filter):
                assert search_filter == "(sAMAccountName=*)"
                assert config["ous"] == ["ou=一部门,dc=example,dc=com", "ou=二部门,dc=example,dc=com"]
                return [
                    {"username": "carol", "name": "Carol", "email": "carol@example.com"},
                    {"username": "admin", "name": "管理员", "email": ""},
                ]

            monkeypatch.setattr("app.ldap_auth._collect", fake_collect)
            imported = client.post(
                "/settings/ldap",
                data={
                    "csrf": csrf_from(client.get("/settings")),
                    "action": "import",
                    "ldap_url": "ldaps://ldap.example.com",
                    "ldap_ous": "ou=一部门,dc=example,dc=com | ou=二部门,dc=example,dc=com",
                    "ldap_bind_dn": "cn=reader,dc=example,dc=com",
                    "ldap_bind_password": "",
                    "ldap_filter": "(sAMAccountName=%(user)s)",
                    "ldap_attr_map": '{"username": "sAMAccountName", "name": "cn", "email": "mail"}',
                    "ldap_enabled": "1",
                },
            )
            assert imported.status_code == 200
            assert "导入 1 个用户，跳过 1 个。" in imported.text
            assert "bind-secret" not in imported.text
            carol = db.get_user_by_name("carol")
            assert carol["kind"] == "ldap"
            assert carol["display_name"] == "Carol"
            assert carol["email"] == "carol@example.com"
            turned_off = client.post(
                "/settings/ldap",
                data={
                    "csrf": csrf_from(client.get("/settings")),
                    "action": "save",
                    "ldap_url": "",
                    "ldap_ous": "",
                    "ldap_bind_dn": "",
                    "ldap_bind_password": "",
                    "ldap_filter": "",
                    "ldap_attr_map": "",
                },
                follow_redirects=False,
            )
            assert turned_off.status_code == 303
            assert db.get_setting("ldap_bind_password") == ""
            client.post("/logout", data={"csrf": csrf_from(client.get("/"))}, follow_redirects=False)
            local_again = client.post(
                "/login",
                data={"csrf": csrf_from(client.get("/login")), "username": "local", "password": "secret2"},
                follow_redirects=False,
            )
            assert local_again.status_code == 303
    finally:
        os.environ["DNS_DATA_DIR"] = previous

