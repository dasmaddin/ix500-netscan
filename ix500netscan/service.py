"""Long-running service: keep the scanner reserved, wait for the button, write PDFs."""
from __future__ import annotations

import collections
import json
import logging
import os
import socket
import threading
import time

from . import __version__, imaging
from . import protocol as P
from .client import AppControl, KeepAlive, LocalIdentity, ScanSession, ScannerError, search
from .config import Config

log = logging.getLogger(__name__)

POLL_INTERVAL = 0.25
MONITOR_INTERVAL = 15.0
BACKOFF_MIN = 5.0
BACKOFF_MAX = 60.0
STATUS_HOST_ID_REJECTED = 0xFFFFFFF9      # -7
PAIRING_HELP = ("The scanner only accepts the host ID of a computer it was paired with. Pair it "
                "once with ScanSnap Home (or ScanSnap Manager) on a Windows or Mac computer, then "
                "restart this service (HOST_ID=auto adopts the paired host ID).")


class ScannerUnreachable(ScannerError):
    """No answer to the search datagram (scanner off, asleep or off Wi-Fi)."""


class HostIdRejected(ScannerError):
    """Reservation refused with status 0xFFFFFFF9: host ID not of a paired computer."""


def format_host_id(host_id: bytes) -> str:
    return ":".join(f"{b:02x}" for b in host_id)


def host_id_hint(advertised: bytes, configured: str = "auto") -> str | None:
    """Warning for the probe command if a reservation would probably be rejected."""
    if configured == "auto" and not any(advertised):
        return ("the scanner advertises no host ID, it has probably never been paired with a "
                "computer; a reservation would be rejected (status 0xFFFFFFF9). " + PAIRING_HELP)
    if configured != "auto" and bytes.fromhex(configured) != advertised:
        return (f"HOST_ID={configured} differs from the host ID the scanner advertises "
                f"({format_host_id(advertised)}); the reservation may be rejected (status "
                "0xFFFFFFF9). Use HOST_ID=auto unless you know better.")
    return None


class Service:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.Lock()
        self._errors: collections.deque = collections.deque(maxlen=10)
        self._mode = self._load_mode()
        self._status = {
            "scanner": {"host": cfg.host, "name": None, "model": None, "reachable": False,
                        "state": "unknown", "last_seen": None},
            "reserved_by_us": False,
            "busy": False,
            "last_scan": None,
        }
        self._host: str | None = cfg.host
        self._me: LocalIdentity | None = None
        self._keepalive: KeepAlive | None = None
        self._trigger: socket.socket | None = None
        self._backoff = BACKOFF_MIN
        self._problem: dict | None = None      # current streak of identical failures
        self.started = time.time()

    # ------------------------------------------------------------------ state
    def _state_file(self) -> str:
        return os.path.join(self.cfg.state_dir, "state.json")

    def _load_mode(self) -> str:
        try:
            with open(self._state_file()) as f:
                mode = json.load(f).get("mode")
            if mode in ("local", "cloud"):
                return mode
        except (OSError, ValueError):
            pass
        return self.cfg.default_mode

    def _save_mode(self) -> None:
        os.makedirs(self.cfg.state_dir, exist_ok=True)
        tmp = self._state_file() + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"mode": self._mode}, f)
        os.replace(tmp, self._state_file())

    @property
    def mode(self) -> str:
        return self._mode

    def set_mode(self, mode: str) -> None:
        if mode not in ("local", "cloud"):
            raise ValueError("mode must be 'local' or 'cloud'")
        with self._lock:
            changed = mode != self._mode
            self._mode = mode
        if changed:
            log.info("mode -> %s", mode)
            self._save_mode()
            self._wake.set()

    def _error(self, msg: str) -> None:
        log.error(msg)
        with self._lock:
            self._errors.appendleft({"time": time.time(), "message": msg})

    def _fail(self, key: str, level: int, msg: str) -> None:
        """Log a failure once per streak; repeats of the same failure go to DEBUG only."""
        now = time.time()
        with self._lock:
            p = self._problem
            repeat = p is not None and p["kind"] == key
            if repeat:
                p.update(last=now, count=p["count"] + 1)
            else:
                self._problem = {"kind": key, "message": msg, "since": now, "last": now, "count": 1}
                self._errors.appendleft({"time": now, "message": msg})
        if repeat:
            log.debug("still failing (%d times): %s", self._problem["count"], msg)
        else:
            log.log(level, msg)

    def _recovered(self, key: str | None = None) -> None:
        """End the current failure streak (only if it is *key*, when given)."""
        with self._lock:
            p = self._problem
            if p is None or (key is not None and p["kind"] != key):
                return
            self._problem = None
        if p["kind"] == "unreachable":
            log.info("scanner reachable again")
        else:
            log.info("recovered after %d failed attempt(s)", p["count"])

    def status(self) -> dict:
        with self._lock:
            s = json.loads(json.dumps(self._status))
            s["mode"] = self._mode
            s["problem"] = dict(self._problem) if self._problem else None
            s["errors"] = list(self._errors)
        s["version"] = __version__
        s["uptime"] = round(time.time() - self.started)
        return s

    def healthy(self) -> bool:
        return not self._stop.is_set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    # ------------------------------------------------------------------ helpers
    def _identity(self) -> LocalIdentity:
        if self._me is None:
            self._me = LocalIdentity.resolve(self._host or "8.8.8.8", self.cfg.iface)
            log.info("local interface %s, %s", self._me.iface, self._me.ip)
        return self._me

    def _locate(self) -> P.SearchResponse:
        me = self._identity()
        target = self._host or "broadcast"
        try:
            found = search(me, self._host or "255.255.255.255")
        except OSError as e:
            raise ScannerUnreachable(f"search toward {target} failed: {e}") from e
        if not found:
            raise ScannerUnreachable(f"no scanner answered at {target}")
        if not self._host:
            r = next((r for r in found if "iX500" in r.model), found[0])
            self._host = r.ip
            self._me = None
            me = self._identity()
            log.info("discovered %s (%s) at %s", r.name, r.model, r.ip)
            found = search(me, self._host) or [r]
        self._record_search(found[0])
        return found[0]

    def _record_search(self, r: P.SearchResponse | None) -> None:
        with self._lock:
            sc = self._status["scanner"]
            if r is None:
                sc.update(reachable=False, state="unreachable")
                return
            sc.update(host=r.ip, name=r.name, model=r.model, reachable=True,
                      state="reserved" if r.reserved else "free" if r.free else f"{r.status:#010x}",
                      last_seen=time.time())

    def _set(self, **kw) -> None:
        with self._lock:
            self._status.update(kw)

    def _sleep(self, seconds: float) -> bool:
        """Wait unless stopped or woken; returns True if the service should stop."""
        self._wake.wait(seconds)
        self._wake.clear()
        return self._stop.is_set()

    # ------------------------------------------------------------------ monitor thread
    def _monitor(self) -> None:
        while not self._stop.wait(MONITOR_INTERVAL):
            if not self._host:
                continue
            try:
                found = search(self._identity(), self._host, timeout=1.5, attempts=1)
                self._record_search(found[0] if found else None)
            except OSError as e:
                log.debug("monitor search failed: %s", e)
                self._record_search(None)

    # ------------------------------------------------------------------ reservation
    def _reserve(self, r: P.SearchResponse) -> None:
        me = self._identity()
        host_id = r.host_id if self.cfg.host_id == "auto" else bytes.fromhex(self.cfg.host_id)
        st = AppControl(r.ip, me).reserve(self.cfg.password, host_id)
        if st == STATUS_HOST_ID_REJECTED:
            raise HostIdRejected(f"scanner rejected host ID {format_host_id(host_id)} "
                                 f"(status 0xFFFFFFF9). {PAIRING_HELP}")
        if st != 0:
            raise ScannerError(f"reservation refused, status {st:#x}: check IX500_PASSWORD")
        self._set(reserved_by_us=True)
        self._keepalive = KeepAlive(r.ip, me)
        self._keepalive.start()
        log.info("reserved %s (%s)", r.name, r.ip)

    def _stop_keepalive(self) -> None:
        if self._keepalive:
            self._keepalive.stop()
            self._keepalive = None

    def _release(self) -> None:
        self._stop_keepalive()
        if not self._status["reserved_by_us"] or not self._host:
            return
        try:
            st = AppControl(self._host, self._identity(), timeout=5).release()
            log.info("released scanner (status %#x)", st)
        except (OSError, ScannerError) as e:
            log.warning("release failed: %s", e)
        self._set(reserved_by_us=False)

    # ------------------------------------------------------------------ trigger
    def _open_trigger(self) -> None:
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        t.bind(("0.0.0.0", P.PORT_TRIGGER))
        t.setblocking(False)
        self._trigger = t

    def _drain_trigger(self, last: int | None, announce: bool = True) -> tuple[bool, int | None]:
        pressed = False
        while self._trigger:
            try:
                data, src = self._trigger.recvfrom(256)
            except BlockingIOError:
                break
            if self._host and src[0] != self._host:
                continue
            t = P.parse_trigger(data)
            if t and t.code == 1 and t.counter != last:
                log.log(logging.INFO if announce else logging.DEBUG,
                        "scan button (trigger #%d)%s", t.counter, "" if announce else ", already handled")
                pressed, last = True, t.counter
        return pressed, last

    # ------------------------------------------------------------------ main loop
    def run(self) -> None:
        self._open_trigger()
        threading.Thread(target=self._monitor, daemon=True, name="monitor").start()
        try:
            while not self._stop.is_set():
                if self._mode == "cloud":
                    if self._status["reserved_by_us"]:
                        self._release()
                    if self._sleep(30):
                        break
                    continue
                if not self._attempt():
                    if self._sleep(self._backoff):
                        break
                    self._backoff = min(self._backoff * 2, BACKOFF_MAX)
        finally:
            self._release()
            if self._trigger:
                self._trigger.close()
            log.info("stopped")

    def _attempt(self) -> bool:
        """Locate, reserve and serve once. Returns False after a failure (caller backs off)."""
        try:
            r = self._locate()
            self._recovered("unreachable")
            self._reserve(r)
            self._recovered()
            self._backoff = BACKOFF_MIN
            self._serve()
            return True
        except ScannerUnreachable as e:
            self._record_search(None)
            self._fail("unreachable", logging.WARNING,
                       f"scanner not reachable ({e}), will keep retrying")
        except HostIdRejected as e:
            self._fail("host_id_rejected", logging.ERROR, str(e))
        except (OSError, ScannerError, P.ProtocolError) as e:
            msg = f"{type(e).__name__}: {e}"
            self._fail(msg, logging.ERROR, msg)
        self._stop_keepalive()
        self._set(reserved_by_us=False, busy=False)
        self._me = None if not self.cfg.host else self._me
        return False

    def _serve(self) -> None:
        host, me = self._host, self._identity()
        session = ScanSession(host, me)
        try:
            log.info("connected: %s", session.initialize())
            _, last = self._drain_trigger(None, announce=False)
            while not self._stop.is_set() and self._mode == "local":
                pressed, last = self._drain_trigger(last)
                if session.hw_status().button:
                    if not pressed:
                        log.info("scan button (hw status)")
                    pressed = True
                if pressed:
                    self._batch(session)
                    session.close()
                    with ScanSession(host, me) as s:
                        s.end_job()
                    session = ScanSession(host, me)
                    time.sleep(1.6)               # trigger is repeated 3x, 500 ms apart
                    _, last = self._drain_trigger(last, announce=False)
                    continue
                if self._wake.wait(POLL_INTERVAL):
                    self._wake.clear()
        finally:
            session.close()

    def _batch(self, session: ScanSession) -> None:
        self._set(busy=True)
        started = time.time()
        try:
            result = session.scan_batch()
            pages = [img.jpeg for img in result.images]
            kept = pages
            if pages and self.cfg.blank_detection:
                kept = imaging.filter_blank(pages, self.cfg.blank_threshold)
            path = None
            if kept:
                path = imaging.write_pdf(kept, self.cfg.output_dir, self.cfg.filename_template,
                                         self.cfg.file_mode)
                log.info("wrote %s (%d of %d pages)", path, len(kept), len(pages))
            else:
                log.info("button pressed but no paper scanned")
            if result.error:
                self._error(result.error)
            self._set(last_scan={"time": started, "duration": round(time.time() - started, 1),
                                 "pages_scanned": len(pages), "pages_kept": len(kept),
                                 "file": os.path.basename(path) if path else None,
                                 "error": result.error})
        finally:
            self._set(busy=False)
