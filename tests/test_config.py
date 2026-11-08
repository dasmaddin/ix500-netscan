import pytest

from ix500netscan.config import Config


def test_defaults():
    c = Config.from_env({})
    assert c.host is None and c.password is None
    assert c.host_id == "auto"
    assert c.default_mode == "local"
    assert c.api_bind == "127.0.0.1" and c.api_port == 8099
    assert c.blank_detection and c.file_mode == 0o644


def test_values():
    c = Config.from_env({"IX500_HOST": "10.0.0.9", "IX500_PASSWORD": "1234",
                         "HOST_ID": "02:11:22:33:44:ff", "BLANK_PAGE_DETECTION": "off",
                         "DEFAULT_MODE": "cloud", "FILE_MODE": "0640"})
    assert c.host == "10.0.0.9" and c.password == "1234"
    assert c.host_id == "0211223344ff"
    assert not c.blank_detection and c.default_mode == "cloud" and c.file_mode == 0o640


@pytest.mark.parametrize("env", [{"DEFAULT_MODE": "usb"}, {"HOST_ID": "xyz"}])
def test_invalid(env):
    with pytest.raises(ValueError):
        Config.from_env(env)
