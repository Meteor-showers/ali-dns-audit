import os
import re
import tempfile
from datetime import datetime

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
    from datetime import datetime

    from app.db import record_stamp

    assert record_stamp(1666501957000) == datetime.fromtimestamp(1666501957).strftime("%Y-%m-%d %H:%M:%S")
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
    recent = datetime.now().isoformat(timespec="seconds")
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
    guest_domains = client.get(f"/sites/{site['id']}/domains")
    assert guest_domains.status_code == 200
    assert "编辑密钥" not in guest_domains.text
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

