"""Entry point: python -m ix500netscan [run|probe]"""
from __future__ import annotations

import argparse
import logging
import signal
import sys

from . import __version__, api
from .client import LocalIdentity, search
from .config import Config
from .service import Service


def probe(cfg: Config) -> int:
    me = LocalIdentity.resolve(cfg.host or "8.8.8.8", cfg.iface)
    found = search(me, cfg.host or "255.255.255.255")
    if not found:
        print("no scanner found")
        return 1
    for r in found:
        state = "reserved" if r.reserved else "free" if r.free else f"{r.status:#010x}"
        print(f"{r.ip}  {r.name}  {r.model}  state={state}  host_id={r.host_id.hex()}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="ix500netscan", description=__doc__)
    ap.add_argument("command", nargs="?", default="run", choices=["run", "probe"])
    args = ap.parse_args()
    cfg = Config.from_env()
    logging.basicConfig(level=cfg.log_level,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if args.command == "probe":
        return probe(cfg)

    service = Service(cfg)
    signal.signal(signal.SIGTERM, lambda *_: service.stop())
    signal.signal(signal.SIGINT, lambda *_: service.stop())
    api.start(service, cfg.api_bind, cfg.api_port)
    logging.getLogger(__name__).info("ix500-netscan %s, mode %s, output %s",
                                     __version__, service.mode, cfg.output_dir)
    service.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
