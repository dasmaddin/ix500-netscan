import datetime as dt
import struct

import pytest

from ix500netscan import protocol as P

MAC = bytes.fromhex("020000aabbcc")       # dummy, locally administered
HOST_ID = bytes.fromhex("0211223344ff")   # dummy
IP = "10.0.0.5"


def test_search_packet_layout():
    pkt = P.build_search(P.SEARCH_MODE_SEARCH, IP, MAC)
    assert len(pkt) == 32
    assert pkt == (b"VENS" + b"\0\0\0\0" + bytes([10, 0, 0, 5]) + MAC + b"\0\0"
                   + b"\0\0\0\xff" + b"\x00\x10" + b"\0" * 6)
    assert P.build_search(P.SEARCH_MODE_KEEPALIVE, IP, MAC)[4:8] == b"\0\0\0\1"


def _search_answer(status=0x00800007):
    d = bytearray(0x84)
    d[0:4] = b"VENS"
    d[0x0C:0x10] = b"\xff" * 4
    d[0x10:0x14] = bytes([10, 0, 0, 9])
    d[0x14:0x1C] = struct.pack(">II", 53218, 53219)
    d[0x1C:0x22] = bytes.fromhex("0080920000aa")
    d[0x24:0x28] = struct.pack(">I", status)
    d[0x28:0x28 + 16] = b"iX500-A0XX000000"
    d[0x68:0x78] = b"ScanSnap iX500  "
    d[0x7C:0x82] = HOST_ID
    return bytes(d)


def test_parse_search_response():
    r = P.parse_search_response(_search_answer())
    assert r.ip == "10.0.0.9"
    assert (r.scan_port, r.app_port) == (53218, 53219)
    assert r.name == "iX500-A0XX000000"
    assert r.model == "ScanSnap iX500"
    assert r.host_id == HOST_ID
    assert r.free and not r.reserved
    assert P.parse_search_response(_search_answer(0x00800004)).reserved


def test_keepalive_ack_is_not_a_search_response():
    assert P.parse_search_response(b"VENS\x80\x01\x00\x00\x00\x00\x00\x00") is None


def test_password_obfuscation():
    # 'A' = 65, key[0] = 'p' = 112: 65 + 11 + 112 = 188
    assert P.obfuscate_password("A")[:3] == b"188"
    field = P.obfuscate_password("1234")
    assert len(field) == 48
    expected = "".join("%03d" % (ord(c) + 11 + P.PASSWORD_KEY[i]) for i, c in enumerate("1234"))
    assert field.rstrip(b"\0").decode() == expected
    with pytest.raises(ValueError):
        P.obfuscate_password("x" * 17)


def test_reserve_packet_layout():
    tz = dt.timezone(dt.timedelta(hours=1))
    now = dt.datetime(2026, 11, 8, 18, 29, 52, tzinfo=tz)
    pkt = P.build_reserve(MAC, IP, "1234", HOST_ID, now=now)
    assert len(pkt) == 0x80
    assert struct.unpack(">I", pkt[0:4])[0] == 0x80
    assert pkt[4:8] == b"VENS"
    assert struct.unpack(">I", pkt[8:12])[0] == 0x11
    assert pkt[0x10:0x18] == MAC + b"\0\0"
    assert pkt[0x20:0x24] == b"\x00\x10\x1e\x00"
    assert struct.unpack(">I", pkt[0x28:0x2C])[0] == 1
    assert pkt[0x2C:0x30] == bytes([10, 0, 0, 5])
    assert struct.unpack(">I", pkt[0x30:0x34])[0] == 55265
    assert pkt[0x34:0x64] == P.obfuscate_password("1234")
    assert pkt[0x64:0x68] == bytes.fromhex("07ea0b08")
    assert pkt[0x68:0x6C] == bytes.fromhex("121d3400")
    assert pkt[0x6C:0x74] == HOST_ID + b"\0\0"
    assert struct.unpack(">i", pkt[0x74:0x78])[0] == -3600
    assert pkt[0x78:] == b"\0" * 8


def test_reserve_without_password():
    pkt = P.build_reserve(MAC, IP, None, HOST_ID)
    assert struct.unpack(">I", pkt[0x28:0x2C])[0] == 0
    assert pkt[0x34:0x64] == b"\0" * 48


def test_release_packet():
    pkt = P.build_release(MAC)
    assert pkt == (b"\x00\x00\x00\x20VENS\x00\x00\x00\x12\x00\x00\x00\x00" + MAC + b"\0\0"
                   + b"\x00\x00\x00\x01" + b"\0" * 4)


def test_app_status_and_greeting():
    assert P.app_status(bytes.fromhex("0000001456454e53000000000006000000000000")) == 0
    P.check_greeting(b"\x00\x00\x00\x10VENS" + b"\0" * 8)
    with pytest.raises(P.ProtocolError):
        P.check_greeting(b"\x00\x00\x00\x10VENS\x00\x00\x00\x01" + b"\0" * 4)


def test_command_header():
    pkt = P.build_command(MAC, P.CDB_SET_PARAMS, 0, P.PARAMS_DATA)
    assert len(pkt) == 0x40 + 0x50
    assert struct.unpack(">I", pkt[0:4])[0] == 0x90
    assert pkt[4:8] == b"VENS"
    assert struct.unpack(">II", pkt[8:16]) == (1, 0)
    assert pkt[0x10:0x18] == MAC + b"\0\0"
    assert struct.unpack(">IIII", pkt[0x20:0x30]) == (6, 0, 0x50, 0)
    assert pkt[0x30:0x40] == P.CDB_SET_PARAMS + b"\0" * 10
    assert pkt[0x40:] == P.PARAMS_DATA


def test_scan_parameter_blocks():
    assert len(P.PREREAD_DATA) == 0x20
    assert len(P.PARAMS_DATA) == 0x50
    assert P.PARAMS_DATA[0x22:0x26] == b"\x01\x2c\x01\x2c"   # 300 x 300 dpi


def test_read_cdbs():
    assert P.cdb_read_image(P.SIDE_FRONT, 0) == bytes.fromhex("280000020000300000000000")
    assert P.cdb_read_image(P.SIDE_BACK, 1) == bytes.fromhex("280000020080300000000100")
    assert P.cdb_read_image_info(P.SIDE_BACK) == bytes.fromhex("280080000080000020000000")


def test_parse_command_response():
    resp = struct.pack(">I", 0x28 + 4) + b"VENS" + struct.pack(">II", 0, 2) + b"\0" * 24 + b"data"
    r = P.parse_command_response(resp)
    assert r.transport == 0 and r.check_condition and r.data == b"data"


def test_sense():
    eom = P.parse_sense(bytes.fromhex("f00060000123450a00000000000000000000"))
    assert eom.end_of_page and eom.ili and eom.info == 0x12345
    empty = P.parse_sense(bytes.fromhex("f00003000000000a00000000800300000000"))
    assert empty.paper_empty and not empty.end_of_page


def test_hw_status_and_trigger():
    hw = P.parse_hw_status(bytes.fromhex("0000008001012000") + b"\0" * 24)
    assert hw.paper_empty and hw.button
    trig = bytes.fromhex("0000003056454e530000000100000000") + b"\x06" + b"\0" * 31
    t = P.parse_trigger(trig)
    assert (t.code, t.counter) == (1, 6)
    assert P.parse_trigger(b"junk") is None
