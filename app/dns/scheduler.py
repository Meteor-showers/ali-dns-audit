from __future__ import annotations

import logging
import os
import threading
from datetime import datetime

from app import db
from app.dns.errors import DnsError
from app.dns.service import check_site_ns, inspect_ns, refresh_domain_records, sync_site_catalog

log = logging.getLogger(__name__)

INTERVAL = 180
FRESH_SECONDS = 120


def enabled() -> bool:
    return os.environ.get("DNS_AUTO_SYNC", "1") != "0"


def is_fresh(stamp: str, limit: int = FRESH_SECONDS) -> bool:
    if not stamp:
        return False
    try:
        then = datetime.fromisoformat(stamp)
    except ValueError:
        return False
    return (datetime.now() - then).total_seconds() < limit


def records_due(zone: dict) -> bool:
    if zone.get("records_error"):
        return False
    return not is_fresh(zone.get("records_synced_at") or "", FRESH_SECONDS)


def ns_due(zone: dict) -> bool:
    return not is_fresh(zone.get("ns_checked_at") or "", INTERVAL)


def site_due(site: dict) -> bool:
    if site.get("last_error") and is_fresh(site.get("last_sync_at") or "", INTERVAL):
        return False
    return not is_fresh(site.get("last_sync_at") or "", INTERVAL)


class Scheduler:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._mu = threading.Lock()
        self._cycle = False
        self._sites: set[int] = set()
        self._zones: set[tuple[int, str]] = set()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not enabled() or self._thread:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="dns-sync", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def kick(self) -> None:
        if enabled():
            self._wake.set()

    def busy(self) -> bool:
        with self._mu:
            return bool(self._sites) or bool(self._zones)

    def busy_site(self, site_id: int) -> bool:
        with self._mu:
            return site_id in self._sites

    def busy_zone(self, site_id: int, domain: str) -> bool:
        key = (site_id, domain.lower())
        with self._mu:
            return key in self._zones

    def watch_site(self, site_id: int) -> bool:
        if not enabled():
            return False
        site = db.get_site(site_id)
        if not site:
            return False
        has_zones = db.zone_counts().get(site_id, 0) > 0
        if self.busy_site(site_id):
            return not has_zones
        if not site_due(site):
            return False
        self._enqueue_site(site_id)
        return not has_zones

    def watch_zone(self, site: dict, zone: dict) -> bool:
        if not enabled():
            return False
        has_records = bool(zone.get("records_synced_at"))
        need_times = (
            has_records
            and not zone.get("records_error")
            and db.records_missing_times(site["id"], zone["domain"])
        )
        need_records = records_due(zone) or need_times
        need_ns = ns_due(zone)
        if not need_records and not need_ns:
            return False
        site_id = site["id"]
        domain = zone["domain"]
        if self.busy_zone(site_id, domain):
            return (not has_records) or need_times
        self._enqueue_zone(site_id, domain, need_records, need_ns)
        return (need_records and not has_records) or need_times

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._run_cycle()
            self._wake.wait(INTERVAL)
            self._wake.clear()

    def _run_cycle(self) -> None:
        with self._mu:
            if self._cycle:
                return
            self._cycle = True
        try:
            for site in db.list_sites():
                if self._stop.is_set():
                    return
                try:
                    sync_site_catalog(site)
                except DnsError:
                    pass
                try:
                    check_site_ns(site["id"])
                except Exception:
                    log.exception("ns check failed for site %s", site.get("id"))
        except Exception:
            log.exception("scheduled sync failed")
        finally:
            with self._mu:
                self._cycle = False

    def _enqueue_site(self, site_id: int) -> bool:
        with self._mu:
            if self._cycle or site_id in self._sites:
                return True
            self._sites.add(site_id)

        def run() -> None:
            try:
                site = db.get_site(site_id)
                if site:
                    sync_site_catalog(site)
            except DnsError:
                pass
            except Exception:
                log.exception("site sync failed")
            finally:
                with self._mu:
                    self._sites.discard(site_id)

        threading.Thread(target=run, daemon=True).start()
        return True

    def _enqueue_zone(self, site_id: int, domain: str, records: bool, ns: bool) -> bool:
        key = (site_id, domain.lower())
        with self._mu:
            if key in self._zones:
                return True
            self._zones.add(key)

        def run() -> None:
            try:
                site = db.get_site(site_id)
                if not site:
                    return
                if records:
                    try:
                        refresh_domain_records(site, domain)
                    except DnsError as exc:
                        db.mark_records_error(site_id, domain, exc.message)
                if ns:
                    outcome = inspect_ns(site["provider"], domain)
                    db.update_zone_ns(
                        site_id,
                        domain,
                        ";".join(outcome["servers"]),
                        outcome["location"],
                        outcome["provider"],
                    )
            except Exception:
                log.exception("zone refresh failed")
                if ns:
                    db.update_zone_ns(site_id, domain, "", "NS查询失败", "")
            finally:
                with self._mu:
                    self._zones.discard(key)

        threading.Thread(target=run, daemon=True).start()
        return True


scheduler = Scheduler()
