"""Network client for the ScanSnap iX500: discovery, App-Control and Scanner-Control."""
from __future__ import annotations

import fcntl
import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

from . import protocol as P

log = logging.getLogger(__name__)

SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927


class ScannerError(Exception):
    pass


# --------------------------------------------------------------------------- local network identity
def local_ip_for(host: str) -> str:
    """IP of the local interface that routes to *host* (no packet is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, P.PORT_SEARCH))
        return s.getsockname()[0]
    finally:
        s.close()


def _ifreq(name: str) -> bytes:
    return struct.pack("256s", name.encode()[:15])


def interface_ip(name: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), SIOCGIFADDR, _ifreq(name))[20:24])
    finally:
        s.close()


def interface_mac(name: str) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, _ifreq(name))[18:24]
    finally:
        s.close()


def interface_for_ip(ip: str) -> str:
    for _, name in socket.if_nameindex():
        try:
            if interface_ip(name) == ip:
                return name
        except OSError:
            continue
    raise ScannerError(f"no network interface carries {ip}")


@dataclass
class LocalIdentity:
    ip: str
    mac: bytes
    iface: str

    @classmethod
    def resolve(cls, toward: str, iface: str | None = None) -> "LocalIdentity":
        if iface:
            ip = interface_ip(iface)
        else:
            ip = local_ip_for(toward)
            iface = interface_for_ip(ip)
        return cls(ip=ip, mac=interface_mac(iface), iface=iface)


# --------------------------------------------------------------------------- discovery
def search(me: LocalIdentity, host: str = "255.255.255.255", timeout: float = 2.0,
           attempts: int = 2) -> list[P.SearchResponse]:
    """Send a search datagram (unicast or broadcast) and collect answers."""
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    found: dict[str, P.SearchResponse] = {}
    try:
        for _ in range(attempts):
            u.sendto(P.build_search(P.SEARCH_MODE_SEARCH, me.ip, me.mac), (host, P.PORT_SEARCH))
            deadline = time.monotonic() + timeout
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                u.settimeout(left)
                try:
                    data, _ = u.recvfrom(2048)
                except socket.timeout:
                    break
                r = P.parse_search_response(data)
                if r:
                    found[r.ip] = r
            if found:
                break
    finally:
        u.close()
    return list(found.values())


class KeepAlive(threading.Thread):
    """Holds a reservation: 3 keep-alive datagrams 500 ms apart every ~12.5 s."""

    def __init__(self, host: str, me: LocalIdentity, interval: float = 12.5):
        super().__init__(daemon=True, name="keepalive")
        self.host, self.me, self.interval = host, me, interval
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        pkt = P.build_search(P.SEARCH_MODE_KEEPALIVE, self.me.ip, self.me.mac)
        try:
            while not self._stop.is_set():
                for _ in range(3):
                    try:
                        u.sendto(pkt, (self.host, P.PORT_SEARCH))
                    except OSError as e:
                        log.debug("keep-alive send failed: %s", e)
                    if self._stop.wait(0.5):
                        return
                self._stop.wait(self.interval - 1.5)
        finally:
            u.close()


# --------------------------------------------------------------------------- TCP helpers
def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = s.recv(min(n - len(buf), 1 << 20))
        if not chunk:
            raise ScannerError(f"connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return bytes(buf)


def _recv_message(s: socket.socket) -> bytes:
    head = _recv_exact(s, 8)
    length = struct.unpack(">I", head[:4])[0]
    if head[4:8] != P.KEYCODE or length < 8:
        raise ScannerError(f"unexpected message header {head.hex()}")
    return head + _recv_exact(s, length - 8)


def _connect(host: str, port: int, timeout: float) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        P.check_greeting(_recv_exact(s, P.GREETING_LEN))
    except Exception:
        s.close()
        raise
    return s


# --------------------------------------------------------------------------- App-Control
class AppControl:
    def __init__(self, host: str, me: LocalIdentity, timeout: float = 10.0):
        self.host, self.me, self.timeout = host, me, timeout

    def request(self, packet: bytes) -> bytes:
        s = _connect(self.host, P.PORT_APP, self.timeout)
        try:
            s.sendall(packet)
            return _recv_message(s)
        finally:
            s.close()

    def reserve(self, password: str | None, host_id: bytes) -> int:
        return P.app_status(self.request(P.build_reserve(self.me.mac, self.me.ip, password, host_id)))

    def release(self) -> int:
        return P.app_status(self.request(P.build_release(self.me.mac)))

    def device_name(self) -> str:
        return P.parse_device_info(self.request(P.build_app_short(P.APP_DEVICE_INFO, self.me.mac)))


# --------------------------------------------------------------------------- Scanner-Control
@dataclass
class Image:
    index: int
    side: int
    jpeg: bytes

    @property
    def side_name(self) -> str:
        return "back" if self.side == P.SIDE_BACK else "front"


@dataclass
class BatchResult:
    images: list[Image] = field(default_factory=list)
    error: str | None = None


class ScanSession:
    """One TCP connection to the Scanner-Control port."""

    def __init__(self, host: str, me: LocalIdentity, timeout: float = 30.0):
        self.me = me
        self.sock = _connect(host, P.PORT_SCAN, timeout)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "ScanSession":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def command(self, cdb: bytes, in_len: int = 0, out: bytes = b"") -> P.CommandResult:
        self.sock.sendall(P.build_command(self.me.mac, cdb, in_len, out))
        result = P.parse_command_response(_recv_message(self.sock))
        if result.transport != 0:
            raise ScannerError(f"transport status {result.transport:#x} for CDB {cdb.hex()}")
        return result

    def sense(self) -> P.Sense:
        return P.parse_sense(self.command(P.CDB_REQUEST_SENSE, 0x12).data)

    def inquiry(self) -> str:
        return self.command(P.CDB_INQUIRY, 0x60).data[8:36].decode("ascii", "replace").strip()

    def hw_status(self) -> P.HwStatus:
        return P.parse_hw_status(self.command(P.CDB_HW_STATUS, 0x20).data)

    def start_job(self) -> None:
        self.command(P.CDB_START_JOB, 8, b"\0" * 8)

    def end_job(self) -> None:
        self.command(P.CDB_END_JOB)

    def initialize(self) -> str:
        """Sequence ScanSnap Home sends after reserving."""
        name = self.inquiry()
        self.hw_status()
        self.start_job()
        self.end_job()
        return name

    def scan_batch(self) -> BatchResult:
        """Feed all sheets in the hopper and read front and back of each."""
        res = BatchResult()
        self.start_job()
        self.command(P.CDB_POWER_INFO, 4)
        self.command(P.CDB_CANCEL)
        self.command(P.CDB_SET_PREREAD, 0, P.PREREAD_DATA)
        self.command(P.CDB_SET_PARAMS, 0, P.PARAMS_DATA)
        self.start_job()
        index = 0
        while True:
            r = self.command(P.CDB_START_PAPER)
            if r.check_condition:
                sense = self.sense()
                if not sense.paper_empty:
                    res.error = f"paper feed stopped: {sense}"
                    log.warning("StartPaper: %s", sense)
                break
            for side in (P.SIDE_FRONT, P.SIDE_BACK):
                r = self.command(P.cdb_read_image(side, index), P.READ_BLOCK)
                if r.check_condition:
                    sense = self.sense()
                    if not sense.end_of_page:
                        res.error = f"read error: {sense}"
                        log.warning("READ %s sheet: %s", side, sense)
                        return res
                self.command(P.cdb_read_image_info(side), 0x20)
                jpeg = P.strip_image_prefix(r.data)
                if not (jpeg[:2] == b"\xff\xd8" and jpeg[-2:] == b"\xff\xd9"):
                    log.warning("image %d is not a complete JPEG (%d bytes)", index, len(jpeg))
                res.images.append(Image(index, side, jpeg))
                index += 1
        return res
