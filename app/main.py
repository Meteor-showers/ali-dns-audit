from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote, urlencode

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app import auth, db
from app.log import configure_logging
from app.dns.errors import DnsError
from app.dns.scheduler import scheduler
from app.dns.service import (
    PROVIDERS,
    add_record,
    check_site_ns,
    default_line,
    delete_record,
    inspect_ns,
    invalidate_zone,
    record_enabled,
    refresh_domain_records,
    line_label,
    line_options,
    record_types_for,
    choose_zone,
    live_zone,
    match_zones,
    normalize_query,
    parse_record,
    probe_site,
    provider_label,
    relative_host,
    sync_all,
    set_record_status,
    sync_site,
    update_record,
    validate_proxy,
)

ROOT = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(ROOT / "templates"))
templates.env.globals["provider_label"] = provider_label
templates.env.globals["line_label"] = line_label
templates.env.globals["record_enabled"] = record_enabled
templates.env.globals["status_label"] = lambda value: {
    "ENABLE": "启用",
    "enable": "启用",
    "DISABLE": "停止",
    "disable": "停止",
    "1": "启用",
    "0": "停止",
}.get(value or "", value or "—")
templates.env.globals["badge_class"] = lambda location: {
    "阿里DNS": "ok",
    "DNSPod": "info",
    "Wix": "info",
    "解析在外站": "bad",
    "公网未委托": "warn",
    "域名不存在": "warn",
    "NS查询失败": "warn",
}.get(location, "muted")
templates.env.globals["display_location"] = lambda location: "公网未委托" if location == "域名不存在" else location
templates.env.globals["quote"] = quote
templates.env.globals["relative_host"] = relative_host


def proxy_mode_label(site: dict) -> str:
    if (site.get("proxy") or "").strip():
        return "平台代理"
    if db.get_setting("global_proxy"):
        return "全局代理"
    return "直连"


templates.env.globals["proxy_mode"] = proxy_mode_label


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init()
    scheduler.start()
    try:
        yield
    finally:
        scheduler.stop()


configure_logging()

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")


def session_secret() -> str:
    path = db.data_dir() / "session.secret"
    if not path.exists():
        path.write_text(secrets.token_hex(32), encoding="utf-8")
    return path.read_text(encoding="utf-8").strip()


def ensure_csrf(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def check_csrf(request: Request, token: str) -> None:
    if not token or token != request.session.get("csrf"):
        raise DnsError("页面已过期，请刷新后重试。")


def flash(request: Request, text: str, level: str = "ok") -> None:
    request.session["flash"] = {"text": text, "level": level}


def actor(request: Request) -> str:
    return str(request.session.get("username") or "")


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client and request.client.host else ""
    forwarded = (request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip") or "").split(",")[0].strip()
    chosen = forwarded if forwarded and _proxy_peer(peer) else peer
    chosen = chosen.strip()
    if chosen.startswith("::ffff:"):
        chosen = chosen[7:]
    return chosen[:64]


def _proxy_peer(peer: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def write_audit(request: Request, action: str, detail: str = "", username: str = "", link: str = "") -> None:
    db.add_audit(username or actor(request) or "—", action, detail, link, client_ip(request))


def start_session(request: Request, user: dict) -> None:
    request.session["user_id"] = int(user["id"])
    request.session["username"] = user["username"]


def signed_in(request: Request) -> bool:
    user_id = request.session.get("user_id")
    if not user_id:
        return False
    return db.get_user(int(user_id)) is not None


def render(request: Request, name: str, status_code: int = 200, **context):
    context.setdefault("csrf", ensure_csrf(request))
    context.setdefault("flash_message", request.session.pop("flash", None))
    context.setdefault("signed_in", signed_in(request))
    context.setdefault("show_nav", True)
    context.setdefault("username", actor(request))
    return templates.TemplateResponse(request, name, context, status_code=status_code)


def page_window(page: int, pages: int) -> list:
    if pages <= 1:
        return []
    if pages <= 7:
        return list(range(1, pages + 1))
    wanted = {1, pages}
    for offset in range(-2, 3):
        number = page + offset
        if 1 <= number <= pages:
            wanted.add(number)
    ordered = sorted(wanted)
    result: list = []
    previous = 0
    for number in ordered:
        if previous and number - previous > 1:
            result.append(None)
        result.append(number)
        previous = number
    return result


templates.env.globals["page_window"] = page_window


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


PAGE_SIZES = (20, 50, 100)
templates.env.globals["page_sizes"] = PAGE_SIZES


def choose_page_size(request: Request, size: int = 0) -> int:
    if size in PAGE_SIZES:
        request.session["page_size"] = size
        return size
    saved = request.session.get("page_size")
    if saved in PAGE_SIZES:
        return int(saved)
    return PAGE_SIZES[0]


def zone_url(site_id: int, domain: str, query: str = "", rq: str = "", page: int = 1, focus: str = "") -> str:
    params = {"site_id": str(site_id), "domain": domain}
    if query:
        params["q"] = query
    if rq:
        params["rq"] = rq
    if page > 1:
        params["page"] = str(page)
    if focus:
        params["focus"] = focus
    url = "/zone?" + urlencode(params)
    if focus:
        url += "#rec-" + quote(str(focus), safe="")
    return url


def zone_link(site_id: int, domain: str, host: str = "") -> str:
    rq = host if host and host != "@" else ""
    return zone_url(site_id, domain, rq=rq)


def ns_view(zone: dict, updating: bool = False) -> dict:
    location = zone.get("ns_location") or "未检查"
    if location == "域名不存在":
        location = "公网未委托"
    servers = [item for item in (zone.get("ns_public") or "").split(";") if item]
    notes = {
        "未检查": "正在查询公网 NS。" if updating else "",
        "公网未委托": "账号里有这个域名，公网还查不到 NS。一般是注册商还没把 DNS 指过来。",
        "NS查询失败": "公网 NS 没有查到，稍后会再查。",
    }
    return {
        "location": location,
        "provider": zone.get("ns_provider") or "",
        "servers": servers,
        "note": notes.get(location, ""),
        "checked_at": zone.get("ns_checked_at") or "",
    }


def guest_allowed(path: str, method: str) -> bool:
    if method == "POST":
        return path == "/login"
    if path in {"/", "/search", "/login", "/zone", "/zone/live", "/sites/live"}:
        return True
    parts = [part for part in path.split("/") if part]
    return len(parts) == 3 and parts[0] == "sites" and parts[1].isdigit() and parts[2] in {"domains", "live"}


@app.middleware("http")
async def auth_gate(request: Request, call_next):
    path = request.url.path
    if path.startswith("/static"):
        return await call_next(request)
    ready = db.has_users()
    authed = signed_in(request)
    if not ready:
        if path != "/setup":
            return redirect("/setup")
        return await call_next(request)
    if path == "/setup":
        return redirect("/")
    if authed and path == "/login":
        return redirect("/")
    if not authed and not guest_allowed(path, request.method):
        return redirect("/login")
    return await call_next(request)


def clean_username(value: str) -> str:
    name = value.strip()
    if not name or len(name) > 32 or any(ch.isspace() for ch in name):
        raise DnsError("用户名需为 1 到 32 个字符，不能含空格。")
    return name


def register_user(username: str, password: str) -> dict:
    if db.get_user_by_name(username):
        raise DnsError("这个用户名已经有了。")
    return auth.create_user(username, password)


@app.get("/setup")
def setup_page(request: Request):
    return render(request, "setup.html", show_nav=False, legacy=db.password_set())


@app.post("/setup")
async def setup_submit(request: Request):
    form = await request.form()
    check_csrf(request, str(form.get("csrf") or ""))
    legacy = db.password_set()
    password = str(form.get("password") or "")
    confirm = str(form.get("confirm") or "")
    try:
        username = clean_username(str(form.get("username") or ""))
        if legacy:
            if not auth.check_password(password):
                raise DnsError("当前密码不正确。")
        else:
            if len(password) < 6:
                raise DnsError("密码至少 6 位。")
            if password != confirm:
                raise DnsError("两次密码不一致。")
        user = register_user(username, password)
    except DnsError as exc:
        return render(request, "setup.html", show_nav=False, legacy=legacy, error=exc.message, status_code=400)
    if legacy:
        db.clear_legacy_password()
    start_session(request, user)
    write_audit(request, "创建账号", username)
    flash(request, "账号已创建。接下来在「平台」里添加各平台密钥。")
    return redirect("/")


@app.get("/login")
def login_page(request: Request):
    return render(request, "login.html", show_nav=False)


@app.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    check_csrf(request, str(form.get("csrf") or ""))
    username = str(form.get("username") or "").strip()[:32]
    password = str(form.get("password") or "")
    user = auth.authenticate(username, password)
    if not user:
        write_audit(request, "登录失败", username=username or "—")
        return render(request, "login.html", show_nav=False, error="用户名或密码不正确。", status_code=400)
    start_session(request, user)
    write_audit(request, "登录")
    return redirect("/")


@app.post("/logout")
async def logout(request: Request):
    form = await request.form()
    check_csrf(request, str(form.get("csrf") or ""))
    write_audit(request, "退出")
    request.session.clear()
    return redirect("/")


@app.get("/")
def home(request: Request):
    authed = signed_in(request)
    sites = db.list_sites() if authed else []
    counts = db.zone_counts() if sites else {}
    attention, attention_total = db.attention_zones(8) if authed and sites else ([], 0)
    recent = db.query_audit("", 1, 6)[0] if authed else []
    return render(
        request,
        "index.html",
        active="search",
        sites=sites,
        counts=counts,
        site_count=len(sites),
        zone_count=sum(counts.values()) if counts else 0,
        attention=attention,
        attention_total=attention_total,
        recent=recent,
    )


@app.get("/search")
def search(request: Request, q: str = ""):
    query = q.strip()
    if not query:
        return redirect("/")
    if not db.list_sites():
        if signed_in(request):
            flash(request, "还没有平台。先到「平台」添加密钥。", "err")
            return redirect("/sites")
        flash(request, "还没有可查询的域名。", "err")
        return redirect("/")
    matches = match_zones(query)
    cleaned = normalize_query(query)
    if not matches:
        return render(request, "search.html", active="search", query=cleaned or query, matches=[])
    zone = choose_zone(matches)
    if zone:
        host = relative_host(cleaned, zone["domain"])
        rq = host if host and host != "@" else ""
        if len(matches) > 1:
            flash(
                request,
                f"公网解析在「{zone['site_name']}」的{provider_label(zone['provider'])}，已打开该平台的解析。",
            )
        return redirect(zone_url(zone["site_id"], zone["domain"], cleaned, rq))
    return render(request, "search.html", active="search", query=cleaned, matches=matches)


@app.get("/settings")
def settings_page(request: Request):
    return render(
        request,
        "settings.html",
        active="settings",
        global_proxy=db.get_setting("global_proxy"),
        users=db.list_users(),
        admin_id=db.first_user_id() or 0,
        user_id=int(request.session.get("user_id") or 0),
    )


@app.post("/settings/proxy")
async def settings_proxy(request: Request):
    form = await request.form()
    try:
        check_csrf(request, str(form.get("csrf") or ""))
        proxy = validate_proxy(str(form.get("global_proxy") or ""))
    except DnsError as exc:
        return render(
            request,
            "settings.html",
            active="settings",
            global_proxy=str(form.get("global_proxy") or ""),
            users=db.list_users(),
            admin_id=db.first_user_id() or 0,
            user_id=int(request.session.get("user_id") or 0),
            error=exc.message,
            status_code=400,
        )
    db.set_setting("global_proxy", proxy)
    write_audit(request, "修改全局代理", "已设置代理" if proxy else "改为直连")
    flash(request, "全局代理已保存。" if proxy else "已改为直连，不再使用全局代理。")
    return redirect("/settings")


@app.post("/settings/password")
async def settings_password(request: Request):
    form = await request.form()
    try:
        check_csrf(request, str(form.get("csrf") or ""))
    except DnsError as exc:
        flash(request, exc.message, "err")
        return redirect("/settings")
    current = str(form.get("current") or "")
    password = str(form.get("password") or "")
    confirm = str(form.get("confirm") or "")
    user_id = int(request.session.get("user_id") or 0)
    if not auth.check_user_password(user_id, current):
        flash(request, "当前密码不正确。", "err")
        return redirect("/settings")
    if len(password) < 6:
        flash(request, "新密码至少 6 位。", "err")
        return redirect("/settings")
    if password != confirm:
        flash(request, "两次新密码不一致。", "err")
        return redirect("/settings")
    auth.set_password(user_id, password)
    write_audit(request, "修改登录密码")
    flash(request, "登录密码已更新。")
    return redirect("/settings")


@app.post("/settings/users")
async def create_user_route(request: Request):
    form = await request.form()
    try:
        check_csrf(request, str(form.get("csrf") or ""))
        username = clean_username(str(form.get("username") or ""))
        password = str(form.get("password") or "")
        confirm = str(form.get("confirm") or "")
        if len(password) < 6:
            raise DnsError("密码至少 6 位。")
        if password != confirm:
            raise DnsError("两次密码不一致。")
        register_user(username, password)
    except DnsError as exc:
        flash(request, exc.message, "err")
        return redirect("/settings")
    write_audit(request, "添加账号", username)
    flash(request, f"账号 {username} 已添加。")
    return redirect("/settings")


@app.post("/settings/users/{user_id}/delete")
async def delete_user_route(request: Request, user_id: int):
    form = await request.form()
    try:
        check_csrf(request, str(form.get("csrf") or ""))
    except DnsError as exc:
        flash(request, exc.message, "err")
        return redirect("/settings")
    if user_id == int(request.session.get("user_id") or 0):
        flash(request, "不能删除当前登录的账号。", "err")
        return redirect("/settings")
    if user_id == db.first_user_id():
        flash(request, "管理账号不能删除。", "err")
        return redirect("/settings")
    user = db.get_user(user_id)
    if not user:
        flash(request, "账号不存在。", "err")
        return redirect("/settings")
    if db.count_users() <= 1:
        flash(request, "至少保留一个账号。", "err")
        return redirect("/settings")
    db.delete_user(user_id)
    write_audit(request, "删除账号", user["username"])
    flash(request, f"账号 {user['username']} 已删除。")
    return redirect("/settings")


@app.get("/audit")
def audit_page(request: Request, q: str = "", page: int = 1, size: int = 0):
    page_size = choose_page_size(request, size)
    rows, total, page, pages = db.query_audit(q, page, page_size)
    return render(
        request,
        "audit.html",
        active="audit",
        rows=rows,
        total=total,
        page=page,
        pages=pages,
        page_size=page_size,
        keyword=q.strip(),
    )


@app.get("/sites")
def sites_page(request: Request):
    return render(
        request,
        "sites.html",
        active="sites",
        sites=db.list_sites(),
        counts=db.zone_counts(),
        updating=scheduler.busy(),
        live_url="/sites/live",
    )


@app.get("/sites/live")
def sites_live():
    return JSONResponse({"pending": scheduler.busy()})


@app.get("/sites/{site_id}/live")
def site_live(site_id: int):
    return JSONResponse({"pending": scheduler.busy_site(site_id)})


@app.get("/zone/live")
def zone_live(site_id: int, domain: str):
    return JSONResponse({"pending": scheduler.busy_zone(site_id, domain)})


@app.post("/sync")
async def sync_everything(request: Request):
    form = await request.form()
    check_csrf(request, str(form.get("csrf") or ""))
    results = sync_all()
    failed = [item for item in results if item["error"]]
    if failed:
        flash(request, "同步结束，有平台失败：" + "；".join(f"{item['site']} {item['error']}" for item in failed), "err")
    else:
        domains = sum(item["count"] for item in results)
        records = sum(item["records"] for item in results)
        flash(request, f"已更新：{len(results)} 个平台，{domains} 个域名，{records} 条解析。")
    write_audit(request, "同步全部", f"{len(results)} 个平台")
    return redirect("/sites")


@app.get("/sites/new")
def new_site_page(request: Request):
    return render(request, "site_form.html", active="sites", site=None, providers=PROVIDERS)


@app.post("/sites")
async def create_site_route(request: Request):
    form = await request.form()
    try:
        check_csrf(request, str(form.get("csrf") or ""))
        data = site_from_form(form)
    except DnsError as exc:
        return render(
            request,
            "site_form.html",
            active="sites",
            site=draft_site(form),
            providers=PROVIDERS,
            error=exc.message,
            status_code=400,
        )
    try:
        probe_site(data)
    except DnsError as exc:
        return render(
            request,
            "site_form.html",
            active="sites",
            site=draft_site(form),
            providers=PROVIDERS,
            error=exc.message,
            status_code=400,
        )
    site_id = db.create_site(data)
    scheduler.kick()
    write_audit(request, "添加平台", f"{data['name']}（{provider_label(data['provider'])}）", link=f"/sites/{site_id}/domains")
    flash(request, "平台已添加，正在获取域名和解析。")
    return redirect(f"/sites/{site_id}/domains")


@app.get("/sites/{site_id}/edit")
def edit_site_page(request: Request, site_id: int):
    site = db.get_site(site_id)
    if not site:
        flash(request, "平台不存在。", "err")
        return redirect("/sites")
    return render(request, "site_form.html", active="sites", site=site, providers=PROVIDERS)


@app.post("/sites/{site_id}")
async def update_site_route(request: Request, site_id: int):
    site = db.get_site(site_id)
    if not site:
        flash(request, "平台不存在。", "err")
        return redirect("/sites")
    form = await request.form()
    try:
        check_csrf(request, str(form.get("csrf") or ""))
        data = site_from_form(form, site)
    except DnsError as exc:
        draft = draft_site(form)
        draft["id"] = site_id
        draft["secret_key"] = site["secret_key"]
        return render(
            request,
            "site_form.html",
            active="sites",
            site=draft,
            providers=PROVIDERS,
            error=exc.message,
            status_code=400,
        )
    try:
        probe_site(data)
    except DnsError as exc:
        draft = draft_site(form)
        draft["id"] = site_id
        draft["secret_key"] = site["secret_key"]
        return render(
            request,
            "site_form.html",
            active="sites",
            site=draft,
            providers=PROVIDERS,
            error=exc.message,
            status_code=400,
        )
    db.update_site(site_id, data)
    scheduler.kick()
    write_audit(request, "修改平台", f"{data['name']}（{provider_label(data['provider'])}）", link=f"/sites/{site_id}/domains")
    flash(request, "平台已更新，正在重新获取域名和解析。")
    return redirect("/sites")


@app.post("/sites/{site_id}/delete")
async def delete_site_route(request: Request, site_id: int):
    form = await request.form()
    check_csrf(request, str(form.get("csrf") or ""))
    site = db.get_site(site_id)
    db.delete_site(site_id)
    if site:
        write_audit(request, "删除平台", site["name"])
    flash(request, "平台已删除。")
    return redirect("/sites")


@app.post("/sites/{site_id}/sync")
async def sync_one(request: Request, site_id: int):
    form = await request.form()
    check_csrf(request, str(form.get("csrf") or ""))
    site = db.get_site(site_id)
    if not site:
        flash(request, "平台不存在。", "err")
        return redirect("/sites")
    try:
        domains, records = sync_site(site)
    except DnsError as exc:
        flash(request, exc.message, "err")
        return redirect("/sites")
    write_audit(request, "同步平台", f"{site['name']}，{domains} 个域名，{records} 条解析", link=f"/sites/{site_id}/domains")
    flash(request, f"{site['name']} 已更新：{domains} 个域名，{records} 条解析。")
    return redirect(f"/sites/{site_id}/domains")


@app.get("/sites/{site_id}/domains")
def site_domains(request: Request, site_id: int, q: str = "", loc: str = "", page: int = 1, size: int = 0):
    site = db.get_site(site_id)
    if not site:
        flash(request, "平台不存在。", "err")
        return redirect("/sites")
    chosen = loc or "live"
    page_size = choose_page_size(request, size)
    updating = scheduler.watch_site(site_id)
    zones, total, page, pages = db.query_zones(
        site_id,
        q,
        "" if chosen == "all" else chosen,
        page,
        page_size,
        site["provider"],
    )
    counts = db.zone_location_counts(site_id)
    own = db.own_ns_location(site["provider"])
    catalog = db.list_zones()
    jumps = {zone["domain"]: live_zone(zone, catalog) for zone in zones}
    jumps = {domain: target for domain, target in jumps.items() if target}
    return render(
        request,
        "domains.html",
        active="sites",
        site=site,
        zones=zones,
        total=total,
        page=page,
        pages=pages,
        keyword=q,
        location=chosen,
        counts=counts,
        live_count=counts.get(own, 0) + counts.get("未检查", 0),
        offsite_count=counts.get("解析在外站", 0),
        all_count=sum(counts.values()),
        jumps=jumps,
        updating=updating,
        page_size=page_size,
        live_url=f"/sites/{site_id}/live",
    )


@app.post("/sites/{site_id}/check-ns")
async def check_ns_route(request: Request, site_id: int):
    form = await request.form()
    check_csrf(request, str(form.get("csrf") or ""))
    site = db.get_site(site_id)
    if not site:
        flash(request, "平台不存在。", "err")
        return redirect("/sites")
    check_site_ns(site_id)
    write_audit(request, "检查公网 NS", site["name"], link=f"/sites/{site_id}/domains")
    flash(request, "公网 NS 已检查。解析不在当前服务商的域名标成「解析在外站」。")
    return redirect(f"/sites/{site_id}/domains")


@app.get("/zone")
def zone_page(request: Request, site_id: int, domain: str, q: str = "", rq: str = "", page: int = 1, size: int = 0, focus: str = ""):
    site = db.get_site(site_id)
    zone = db.get_zone(site_id, domain) if site else None
    if not site or not zone:
        flash(request, "没有找到这个域名。如果刚添加平台，等一会儿再查。", "err")
        return redirect("/search?q=" + quote(q or domain))
    page_size = choose_page_size(request, size)
    if request.query_params.get("stay") != "1":
        target = live_zone(zone, db.list_zones())
        if target:
            flash(
                request,
                f"公网解析在「{target['site_name']}」的{provider_label(target['provider'])}，已打开该平台的解析。",
            )
            return redirect(zone_url(target["site_id"], target["domain"], q, rq, page))
    updating = scheduler.watch_zone(site, zone)
    error = zone.get("records_error") or ""
    detail = ""
    others = [
        item
        for item in db.list_zones()
        if item["domain"].lower() == domain.lower() and item["site_id"] != site_id
    ]
    records, total, page, pages = db.query_records(site_id, domain, rq, page, page_size)
    return render(
        request,
        "zone.html",
        active="search" if q else "sites",
        site=site,
        zone=zone,
        domain=domain,
        query=q,
        rq=rq,
        ns=ns_view(zone, updating),
        updating=updating,
        live_url="/zone/live?" + urlencode({"site_id": str(site_id), "domain": domain}),
        records=records,
        total=total,
        page=page,
        pages=pages,
        page_size=page_size,
        highlight=rq.strip(),
        focus=focus,
        record_error=error,
        detail=detail,
        record_types=record_types_for(site["provider"]),
        lines=line_options(site["provider"]),
        default_ttl=600,
        default_line=default_line(site["provider"]),
        others=others,
    )


@app.post("/zone/refresh")
async def refresh_zone_records(request: Request):
    form = await request.form()
    site_id = int(form.get("site_id") or 0)
    domain = str(form.get("domain") or "")
    query = str(form.get("q") or "")
    rq = str(form.get("rq") or "")
    try:
        check_csrf(request, str(form.get("csrf") or ""))
        site = require_zone(site_id, domain)
        count = refresh_domain_records(site, domain)
    except DnsError as exc:
        db.mark_records_error(site_id, domain, exc.message)
        flash(request, exc.message, "err")
        return redirect(zone_url(site_id, domain, query, rq))
    write_audit(request, "刷新解析", f"{domain}，{count} 条", link=zone_link(site_id, domain))
    flash(request, f"解析已更新，共 {count} 条。")
    return redirect(zone_url(site_id, domain, query, rq))


@app.post("/zone/check-ns")
async def check_zone_ns(request: Request):
    form = await request.form()
    site_id = int(form.get("site_id") or 0)
    domain = str(form.get("domain") or "")
    query = str(form.get("q") or "")
    rq = str(form.get("rq") or "")
    check_csrf(request, str(form.get("csrf") or ""))
    site = db.get_site(site_id)
    if not site or not db.get_zone(site_id, domain):
        flash(request, "没有找到这个域名。", "err")
        return redirect("/")
    outcome = inspect_ns(site["provider"], domain)
    db.update_zone_ns(site_id, domain, ";".join(outcome["servers"]), outcome["location"], outcome["provider"])
    write_audit(request, "检查公网 NS", f"{domain} {outcome['location']}", link=zone_link(site_id, domain))
    flash(request, f"公网 NS：{outcome['location']}")
    return redirect(zone_url(site_id, domain, query, rq))


@app.post("/zone/records")
async def create_record_route(request: Request):
    form = await request.form()
    site_id = int(form.get("site_id") or 0)
    domain = str(form.get("domain") or "")
    query = str(form.get("q") or "")
    try:
        check_csrf(request, str(form.get("csrf") or ""))
        site = require_zone(site_id, domain)
        record = parse_record(form, site["provider"])
        invalidate_zone(site_id, domain)
        add_record(site, domain, record)
        refresh_domain_records(site, domain)
    except DnsError as exc:
        flash(request, exc.message, "err")
        return redirect(zone_url(site_id, domain, query, str(form.get("rq") or "")))
    write_audit(request, "添加解析", record_detail(domain, record), link=zone_link(site_id, domain, record.get("host") or ""))
    flash(request, "解析记录已添加。")
    return redirect(zone_url(site_id, domain, query, record["host"]))


@app.get("/zone/record")
def edit_record_page(request: Request, site_id: int, domain: str, record_id: str, q: str = "", rq: str = ""):
    site = db.get_site(site_id)
    if not site or not db.get_zone(site_id, domain):
        flash(request, "没有找到这个域名。", "err")
        return redirect("/")
    record = db.get_record(site_id, domain, record_id)
    if not record:
        flash(request, "没有找到这条解析记录。", "err")
        return redirect(zone_url(site_id, domain, q, rq))
    return render(
        request,
        "record_edit.html",
        active="search",
        site=site,
        domain=domain,
        query=q,
        rq=rq,
        record=record,
        record_types=record_types_for(site["provider"])
        + ([] if record["type"] in record_types_for(site["provider"]) else [record["type"]]),
        lines=line_options(site["provider"], record["line"]),
    )


@app.post("/zone/record")
async def update_record_route(request: Request):
    form = await request.form()
    site_id = int(form.get("site_id") or 0)
    domain = str(form.get("domain") or "")
    query = str(form.get("q") or "")
    rq = str(form.get("rq") or "")
    inline = str(form.get("inline") or "") == "1"
    record_id = str(form.get("record_id") or "")
    try:
        page = int(form.get("page") or 1)
    except ValueError:
        page = 1
    try:
        check_csrf(request, str(form.get("csrf") or ""))
        site = require_zone(site_id, domain)
        record = parse_record(form, site["provider"])
        if not record["id"]:
            raise DnsError("缺少记录 ID。")
        invalidate_zone(site_id, domain)
        update_record(site, domain, record)
        refresh_domain_records(site, domain)
    except DnsError as exc:
        flash(request, exc.message, "err")
        return redirect(zone_url(site_id, domain, query, rq, page if inline else 1, record_id if inline else ""))
    write_audit(request, "修改解析", record_detail(domain, record), link=zone_link(site_id, domain, record.get("host") or ""))
    flash(request, "解析记录已更新。")
    if inline:
        return redirect(zone_url(site_id, domain, query, rq, page, record["id"]))
    return redirect(zone_url(site_id, domain, query, rq or record["host"]))


@app.post("/zone/record/status")
async def record_status_route(request: Request):
    form = await request.form()
    site_id = int(form.get("site_id") or 0)
    domain = str(form.get("domain") or "")
    query = str(form.get("q") or "")
    rq = str(form.get("rq") or "")
    record_id = str(form.get("record_id") or "")
    want = str(form.get("status") or "")
    try:
        check_csrf(request, str(form.get("csrf") or ""))
        site = require_zone(site_id, domain)
        if not record_id:
            raise DnsError("缺少记录 ID。")
        if want not in {"enable", "disable"}:
            raise DnsError("状态不正确。")
        current = db.get_record(site_id, domain, record_id)
        invalidate_zone(site_id, domain)
        set_record_status(site, domain, record_id, want == "enable")
        refresh_domain_records(site, domain)
    except DnsError as exc:
        flash(request, exc.message, "err")
        return redirect(zone_url(site_id, domain, query, rq))
    write_audit(
        request,
        "启用解析" if want == "enable" else "停止解析",
        record_detail(domain, current, record_id),
        link=zone_link(site_id, domain, (current or {}).get("host") or ""),
    )
    flash(request, "解析已启用。" if want == "enable" else "解析已停止。")
    return redirect(zone_url(site_id, domain, query, rq))


@app.post("/zone/record/delete")
async def delete_record_route(request: Request):
    form = await request.form()
    site_id = int(form.get("site_id") or 0)
    domain = str(form.get("domain") or "")
    query = str(form.get("q") or "")
    rq = str(form.get("rq") or "")
    record_id = str(form.get("record_id") or "")
    try:
        check_csrf(request, str(form.get("csrf") or ""))
        site = require_zone(site_id, domain)
        if not record_id:
            raise DnsError("缺少记录 ID。")
        current = db.get_record(site_id, domain, record_id)
        invalidate_zone(site_id, domain)
        delete_record(site, domain, record_id)
        refresh_domain_records(site, domain)
    except DnsError as exc:
        flash(request, exc.message, "err")
        return redirect(zone_url(site_id, domain, query, rq))
    write_audit(
        request,
        "删除解析",
        record_detail(domain, current, record_id),
        link=zone_link(site_id, domain, (current or {}).get("host") or ""),
    )
    flash(request, "解析记录已删除。")
    return redirect(zone_url(site_id, domain, query, rq))


def record_detail(domain: str, record: dict | None, record_id: str = "") -> str:
    if not record:
        return f"{domain}  #{record_id}" if record_id else domain
    host = record.get("host") or "@"
    return f"{domain}  {host}  {record.get('type') or ''}  {record.get('value') or ''}".strip()


def require_zone(site_id: int, domain: str) -> dict:
    site = db.get_site(site_id)
    if not site or not db.get_zone(site_id, domain):
        raise DnsError("没有找到这个域名。")
    return site


def site_from_form(form, existing: dict | None = None) -> dict:
    name = str(form.get("name") or "").strip()
    provider = str(form.get("provider") or "").strip()
    access_key = str(form.get("access_key") or "").strip()
    secret = str(form.get("secret_key") or "").strip()
    proxy = str(form.get("proxy") or "")
    remark = str(form.get("remark") or "").strip()
    if not name:
        raise DnsError("请填写平台名称。")
    if provider not in PROVIDERS:
        raise DnsError("请选择服务商。")
    if not access_key:
        raise DnsError("请填写密钥 ID。")
    if not secret:
        if not existing:
            raise DnsError("请填写密钥。")
        secret = existing["secret_key"]
    return {
        "name": name,
        "provider": provider,
        "access_key": access_key,
        "secret_key": secret,
        "proxy": validate_proxy(proxy),
        "remark": remark,
    }


def draft_site(form) -> dict:
    return {
        "id": None,
        "name": str(form.get("name") or ""),
        "provider": str(form.get("provider") or "aliyun"),
        "access_key": str(form.get("access_key") or ""),
        "proxy": str(form.get("proxy") or ""),
        "remark": str(form.get("remark") or ""),
    }


@app.exception_handler(DnsError)
async def handle_dns_error(request: Request, exc: DnsError):
    flash(request, exc.message, "err")
    referer = request.headers.get("referer")
    return redirect(referer or "/")


app.add_middleware(
    SessionMiddleware,
    secret_key=session_secret(),
    session_cookie="dns_session",
    max_age=60 * 60 * 24 * 7,
    same_site="lax",
    https_only=False,
)
