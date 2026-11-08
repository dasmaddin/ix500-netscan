"""Wire format of the ScanSnap iX500 Wi-Fi protocol.

Pure functions only: building and parsing packets. No sockets here.
All multi-byte integers are big endian unless noted. See docs/PROTOCOL.md.
"""
from __future__ import annotations

import datetime as _dt
import socket
import struct
from dataclasses import dataclass

KEYCODE = b"VENS"
VERSION = 0x0010

PORT_SEARCH = 52217   # UDP, PC -> scanner: search and keep-alive
PORT_SCAN = 53218     # TCP, PC -> scanner: SCSI-like commands and image data
PORT_APP = 53219      # TCP, PC -> scanner: reserve / release / device info
PORT_TRIGGER = 55265  # UDP, scanner -> PC: scan button pressed

SEARCH_MODE_SEARCH = 0
SEARCH_MODE_KEEPALIVE = 1

APP_RESERVE = 0x11
APP_RELEASE = 0x12
APP_DEVICE_INFO = 0x13
APP_WIFI_STATUS = 0x30

STATUS_FREE = 0x07
STATUS_RESERVED = 0x04

PASSWORD_KEY = b"pFusCANsNapFiPfu"
PASSWORD_FIELD_LEN = 48
MAX_PASSWORD_LEN = 16

SIDE_FRONT = 0x00
SIDE_BACK = 0x80
READ_BLOCK = 0x300000

GREETING_LEN = 16
RESPONSE_HEADER_LEN = 0x28
COMMAND_HEADER_LEN = 0x40


class ProtocolError(Exception):
    pass


def _mac8(mac: bytes) -> bytes:
    if len(mac) != 6:
        raise ValueError("MAC address must be 6 bytes")
    return mac + b"\0\0"


def _ip(ip: str) -> bytes:
    return socket.inet_aton(ip)


def frame(body: bytes) -> bytes:
    """Prefix a message body (starting with the keycode) with its total length."""
    return struct.pack(">I", 4 + len(body)) + body


# --------------------------------------------------------------------------- UDP search
def build_search(mode: int, ip: str, mac: bytes) -> bytes:
    """32-byte search (mode 0) or keep-alive (mode 1) datagram."""
    return (KEYCODE + struct.pack(">I", mode) + _ip(ip) + _mac8(mac)
            + b"\0\0\0\xff" + struct.pack(">H", VERSION) + b"\0" * 6)


@dataclass
class SearchResponse:
    ip: str
    scan_port: int
    app_port: int
    mac: bytes
    status: int
    name: str
    model: str
    host_id: bytes

    @property
    def reserved(self) -> bool:
        return (self.status & 0xFF) == STATUS_RESERVED

    @property
    def free(self) -> bool:
        return (self.status & 0xFF) == STATUS_FREE


def parse_search_response(data: bytes) -> SearchResponse | None:
    """Parse a 132-byte search answer. Returns None for keep-alive acks and foreign data."""
    if len(data) < 0x84 or data[:4] != KEYCODE:
        return None
    return SearchResponse(
        ip=socket.inet_ntoa(data[0x10:0x14]),
        scan_port=struct.unpack(">I", data[0x14:0x18])[0],
        app_port=struct.unpack(">I", data[0x18:0x1C])[0],
        mac=data[0x1C:0x22],
        status=struct.unpack(">I", data[0x24:0x28])[0],
        name=data[0x28:0x68].split(b"\0")[0].decode("ascii", "replace"),
        model=data[0x68:0x78].split(b"\0")[0].decode("ascii", "replace").strip(),
        host_id=data[0x7C:0x82],
    )


# --------------------------------------------------------------------------- App-Control
def obfuscate_password(password: str) -> bytes:
    """Encode the scanner password the way ScanSnap software does (not encryption)."""
    raw = password.encode("ascii")
    if len(raw) > MAX_PASSWORD_LEN:
        raise ValueError(f"password longer than {MAX_PASSWORD_LEN} characters")
    digits = "".join("%03d" % (c + 0x0B + PASSWORD_KEY[i]) for i, c in enumerate(raw))
    return digits.encode("ascii").ljust(PASSWORD_FIELD_LEN, b"\0")


def build_reserve(mac: bytes, ip: str, password: str | None, host_id: bytes,
                  trigger_port: int = PORT_TRIGGER,
                  now: _dt.datetime | None = None) -> bytes:
    """128-byte reservation (App-Control 0x11)."""
    if len(host_id) != 6:
        raise ValueError("host ID must be 6 bytes")
    now = (now or _dt.datetime.now()).astimezone()
    bias = -int(now.utcoffset().total_seconds())
    pw_flag = 1 if password else 0
    pw_field = obfuscate_password(password) if password else b"\0" * PASSWORD_FIELD_LEN
    body = (KEYCODE
            + struct.pack(">II", APP_RESERVE, 0)
            + _mac8(mac) + b"\0" * 8
            + struct.pack(">HBB", VERSION, 0x1E, 0)
            + struct.pack(">II", 0, pw_flag)
            + _ip(ip) + struct.pack(">I", trigger_port)
            + pw_field
            + struct.pack(">HBB", now.year, now.month, now.day)
            + struct.pack(">BBBB", now.hour, now.minute, now.second, 0)
            + _mac8(host_id)
            + struct.pack(">i", bias)
            + b"\0" * 8)
    pkt = frame(body)
    assert len(pkt) == 0x80, len(pkt)
    return pkt


def build_release(mac: bytes) -> bytes:
    """32-byte release (App-Control 0x12): scanner becomes free again (cloud mode)."""
    return frame(KEYCODE + struct.pack(">II", APP_RELEASE, 0) + _mac8(mac)
                 + struct.pack(">I", 1) + b"\0" * 4)


def build_app_short(code: int, mac: bytes) -> bytes:
    """32-byte short App-Control request (device info 0x13, Wi-Fi status 0x30)."""
    return frame(KEYCODE + struct.pack(">II", code, 0) + _mac8(mac) + b"\0" * 8)


def app_status(resp: bytes) -> int:
    """Status word of an App-Control answer; 0 means OK."""
    if len(resp) < 12 or resp[4:8] != KEYCODE:
        raise ProtocolError(f"bad App-Control answer: {resp[:16].hex()}")
    return struct.unpack(">I", resp[8:12])[0]


def parse_device_info(resp: bytes) -> str:
    return resp[0x10:0x50].split(b"\0")[0].decode("ascii", "replace")


def check_greeting(data: bytes) -> None:
    if len(data) != GREETING_LEN or data[4:8] != KEYCODE:
        raise ProtocolError(f"unexpected greeting: {data.hex()}")
    status = struct.unpack(">I", data[8:12])[0]
    if status != 0:
        raise ProtocolError(f"scanner greeting status {status:#x}")


# --------------------------------------------------------------------------- Scanner-Control
def build_command(mac: bytes, cdb: bytes, in_len: int = 0, out: bytes = b"") -> bytes:
    """64-byte command header + outgoing data."""
    if not 1 <= len(cdb) <= 16:
        raise ValueError("CDB must be 1..16 bytes")
    body = (KEYCODE + struct.pack(">II", 1, 0) + _mac8(mac) + b"\0" * 8
            + struct.pack(">IIII", len(cdb), in_len, len(out), 0)
            + cdb.ljust(16, b"\0") + out)
    return frame(body)


@dataclass
class CommandResult:
    transport: int
    scsi: int
    data: bytes

    @property
    def check_condition(self) -> bool:
        return self.scsi == 2


def parse_command_response(resp: bytes) -> CommandResult:
    if len(resp) < RESPONSE_HEADER_LEN or resp[4:8] != KEYCODE:
        raise ProtocolError(f"bad command answer: {resp[:16].hex()}")
    transport, scsi = struct.unpack(">II", resp[8:16])
    return CommandResult(transport, scsi, resp[RESPONSE_HEADER_LEN:])


# CDBs observed from ScanSnap Home (profile "auto": colour, 300 dpi, duplex, JPEG)
CDB_INQUIRY = bytes.fromhex("120000006000")
CDB_HW_STATUS = bytes.fromhex("c2000000000000002000")
CDB_POWER_INFO = bytes.fromhex("e600010000000004")
CDB_START_JOB = bytes.fromhex("d50000000808")
CDB_END_JOB = bytes.fromhex("d60000000000")
CDB_CANCEL = bytes.fromhex("d80000000000")
CDB_SET_PREREAD = bytes.fromhex("e9000000000000200000")
CDB_SET_PARAMS = bytes.fromhex("d40000005000")
CDB_START_PAPER = bytes.fromhex("e00000000000")
CDB_REQUEST_SENSE = bytes.fromhex("030000001200")

PREREAD_DATA = bytes.fromhex("012c012c000028d0000045a405000000") + b"\0" * 16
PARAMS_DATA = bytes.fromhex(
    "00030101d000c180808090808000800100000000000000000000000000000030"
    "0010012c012c05810000000028d00000"
    "45a40000000000000000000000000000"
    "00000000000000000000000000000000")


def cdb_read_image(side: int, index: int, length: int = READ_BLOCK) -> bytes:
    return bytes([0x28, 0, 0, 2, 0, side,
                  (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF,
                  0, index & 0xFF, 0])


def cdb_read_image_info(side: int) -> bytes:
    return bytes([0x28, 0, 0x80, 0, 0, side, 0, 0, 0x20, 0, 0, 0])


@dataclass
class Sense:
    key: int
    asc: int
    ascq: int
    eom: bool
    ili: bool
    info: int

    @property
    def paper_empty(self) -> bool:
        return self.key == 3 and self.asc == 0x80 and self.ascq == 0x03

    @property
    def end_of_page(self) -> bool:
        return self.key == 0 and self.eom

    def __str__(self) -> str:
        return (f"key={self.key:#x} asc={self.asc:#04x} ascq={self.ascq:#04x}"
                f"{' EOM' if self.eom else ''}{' ILI' if self.ili else ''}")


def parse_sense(data: bytes) -> Sense:
    if len(data) < 14:
        raise ProtocolError(f"short sense data: {data.hex()}")
    return Sense(key=data[2] & 0x0F, asc=data[12], ascq=data[13],
                 eom=bool(data[2] & 0x40), ili=bool(data[2] & 0x20),
                 info=struct.unpack(">I", data[3:7])[0])


@dataclass
class HwStatus:
    paper_empty: bool
    button: bool


def parse_hw_status(data: bytes) -> HwStatus:
    if len(data) < 5:
        raise ProtocolError(f"short hardware status: {data.hex()}")
    return HwStatus(paper_empty=bool(data[3] & 0x80), button=bool(data[4] & 0x01))


@dataclass
class Trigger:
    code: int
    counter: int


def parse_trigger(data: bytes) -> Trigger | None:
    if len(data) < 0x11 or data[4:8] != KEYCODE:
        return None
    return Trigger(code=struct.unpack(">I", data[8:12])[0], counter=data[0x10])


def strip_image_prefix(data: bytes) -> bytes:
    """READ data = 2-byte prefix (image number, 0) + JPEG."""
    return data[2:]
