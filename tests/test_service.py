import logging

import pytest

from ix500netscan import service as S
from ix500netscan.client import ScannerError
from ix500netscan.config import Config

HOST_ID = bytes.fromhex("0211223344ff")   # dummy


class _Scanner:
    def __init__(self):
        self.ip, self.name, self.host_id = "10.0.0.9", "iX500-A0XX000000", HOST_ID


@pytest.fixture
def svc(tmp_path, monkeypatch):
    cfg = Config.from_env({"IX500_HOST": "10.0.0.9", "STATE_DIR": str(tmp_path)})
    s = S.Service(cfg)
    monkeypatch.setattr(s, "_identity", lambda: None)
    monkeypatch.setattr(s, "_serve", lambda: None)
    return s


def _records(caplog, level):
    return [r for r in caplog.records if r.name == S.log.name and r.levelno == level]


def test_unreachable_logged_once_then_recovery(svc, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(S, "search", lambda *a, **k: [])
    for _ in range(4):
        assert svc._attempt() is False
    warnings = _records(caplog, logging.WARNING)
    assert len(warnings) == 1 and "not reachable" in warnings[0].getMessage()
    assert not _records(caplog, logging.ERROR)
    assert len([r for r in _records(caplog, logging.DEBUG) if "still failing" in r.getMessage()]) == 3

    st = svc.status()
    assert st["scanner"]["reachable"] is False and st["scanner"]["state"] == "unreachable"
    assert st["problem"]["kind"] == "unreachable" and st["problem"]["count"] == 4
    assert len(st["errors"]) == 1

    monkeypatch.setattr(svc, "_locate", lambda: _Scanner())
    monkeypatch.setattr(svc, "_reserve", lambda r: None)
    caplog.clear()
    assert svc._attempt() is True
    infos = [r.getMessage() for r in _records(caplog, logging.INFO)]
    assert infos == ["scanner reachable again"]
    assert svc.status()["problem"] is None


def test_search_oserror_counts_as_unreachable(svc, monkeypatch, caplog):
    def boom(*a, **k):
        raise OSError(101, "Network is unreachable")
    monkeypatch.setattr(S, "search", boom)
    caplog.set_level(logging.DEBUG)
    svc._attempt()
    svc._attempt()
    assert len(_records(caplog, logging.WARNING)) == 1
    assert svc.status()["problem"]["kind"] == "unreachable"


def test_host_id_rejected_logged_once(svc, monkeypatch, caplog):
    class App:
        def __init__(self, *a, **k):
            pass

        def reserve(self, password, host_id):
            return S.STATUS_HOST_ID_REJECTED

    monkeypatch.setattr(svc, "_locate", lambda: _Scanner())
    monkeypatch.setattr(S, "AppControl", App)
    caplog.set_level(logging.DEBUG)
    for _ in range(3):
        assert svc._attempt() is False
    errors = _records(caplog, logging.ERROR)
    assert len(errors) == 1
    msg = errors[0].getMessage()
    assert "0xFFFFFFF9" in msg and "paired" in msg and "ScanSnap Home" in msg
    assert "02:11:22:33:44:ff" in msg
    assert svc.status()["problem"]["kind"] == "host_id_rejected"


def test_other_errors_repeat_quietly_and_reset(svc, monkeypatch, caplog):
    calls = {"n": 0}

    def locate():
        calls["n"] += 1
        raise ScannerError("boom")

    monkeypatch.setattr(svc, "_locate", locate)
    caplog.set_level(logging.DEBUG)
    svc._attempt()
    svc._attempt()
    assert len(_records(caplog, logging.ERROR)) == 1
    monkeypatch.setattr(svc, "_locate", lambda: _Scanner())
    monkeypatch.setattr(svc, "_reserve", lambda r: None)
    assert svc._attempt() is True
    assert svc.status()["problem"] is None


def test_host_id_hint():
    assert S.host_id_hint(HOST_ID) is None
    assert "never been paired" in S.host_id_hint(b"\0" * 6)
    assert S.host_id_hint(HOST_ID, "0211223344ff") is None
    assert "differs" in S.host_id_hint(HOST_ID, "020000000001")
