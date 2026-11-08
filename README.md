# ix500-netscan

Scan from a Fujitsu/PFU **ScanSnap iX500 over Wi-Fi straight into a folder** — no ScanSnap Home,
no ScanSnap Cloud, no Windows or Mac. Press the scan button and a PDF appears in a directory of
your choice, for example the consume folder of [Paperless-ngx](https://docs.paperless-ngx.com/).

The service talks the iX500's own network protocol (reverse engineered for interoperability, see
[docs/PROTOCOL.md](docs/PROTOCOL.md)). It runs as a small Python program, ideally in Docker on an
always-on Linux box.

## Features

- Reacts to the scanner's **scan button**; scans every sheet in the feeder, front and back
- One **PDF per button press**, JPEG pages embedded losslessly (300 dpi, colour)
- **Blank page removal** (empty backs of single-sided sheets)
- Atomic writes: files appear complete, never half-written
- **Mode switch** `local` ↔ `cloud` via a small JSON API: release the scanner so ScanSnap Cloud or
  ScanSnap Home can use it again
- Reconnects on its own when the scanner sleeps, is switched off or drops off Wi-Fi

## Requirements

- ScanSnap iX500 connected to your Wi-Fi network (configure Wi-Fi once with PFU's tools)
- The scanner must have been **paired with a computer once** (ScanSnap Home or ScanSnap Manager).
  The scanner only accepts the host ID of a paired computer; `HOST_ID=auto` adopts it.
- Linux host in the same network, Docker with host networking (or Python 3.12 + `pip install -r requirements.txt`)
- UDP port 55265 must be reachable on the host (the scanner sends button events there)

## Quick start (Docker)

```sh
git clone https://github.com/dasmaddin/ix500-netscan.git
cd ix500-netscan
cp .env.example .env            # set IX500_PASSWORD, optionally IX500_HOST
cp docker-compose.example.yml docker-compose.yml   # adjust the output volume
docker compose up -d --build
docker compose logs -f
```

Find your scanner first:

```sh
docker compose run --rm ix500-netscan probe
# 192.168.1.50  iX500-A0XX000000  ScanSnap iX500  state=free  host_id=...
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `IX500_HOST` | *(empty)* | Scanner IP; empty = discover by broadcast |
| `IX500_PASSWORD` | *(empty)* | Scanner password. Factory default per PFU: last 4 digits of the serial number |
| `IX500_IFACE` | *(auto)* | Local interface toward the scanner |
| `HOST_ID` | `auto` | Host ID sent when reserving; `auto` = the one the scanner advertises |
| `OUTPUT_DIR` | `/output` | Where PDFs go |
| `FILENAME_TEMPLATE` | `scan_%Y%m%d_%H%M%S.pdf` | `strftime` pattern; `_2`, `_3` … on collision |
| `BLANK_PAGE_DETECTION` | `on` | Drop blank pages |
| `BLANK_PAGE_THRESHOLD` | `0.0025` | Share of ink pixels below which a page counts as blank |
| `FILE_MODE` | `0644` | Permissions of written PDFs |
| `DEFAULT_MODE` | `local` | Mode on first start (`local` or `cloud`); later the last chosen mode is kept |
| `API_BIND` / `API_PORT` | `127.0.0.1` / `8099` | JSON API |
| `STATE_DIR` | `/state` | Persists the chosen mode |
| `LOG_LEVEL` | `INFO` | |

Files are written as the container user (UID/GID 1000 by default, change with build args `UID`/`GID`).

## API

```
GET  /health            {"ok": true}
GET  /api/status        mode, scanner state (free/reserved), last scan, recent errors
POST /api/mode          {"mode": "local"} or {"mode": "cloud"}
```

The API has no authentication. It listens on localhost by default; put a reverse proxy with access
control in front of it if you expose it.

## How it works

1. Find the scanner (UDP 52217) and **reserve** it (TCP 53219). While reserved, the scanner is in
   "computer mode" and sends button presses to this host.
2. Keep the reservation alive with a datagram every ~12 s. Without it the scanner returns to
   being free (and to ScanSnap Cloud, if configured) after about 45 seconds.
3. Keep a command connection open (TCP 53218), wait for the button, then feed the sheets and read
   JPEG images page by page.
4. `cloud` mode simply releases the reservation.

Scan settings are fixed to what ScanSnap Home's "auto" profile sends: colour, 300 dpi, duplex,
JPEG. Other settings are not implemented yet.

## Security note

The iX500 protects its network functions only with a short password. Change the factory password
(PFU's Wi-Fi setup tool) if untrusted devices share your network.

## Disclaimer

Not affiliated with PFU or Fujitsu. ScanSnap is a trademark of PFU Limited. The protocol was
analysed for interoperability with the owner's own device; this project contains no PFU code.
Use at your own risk.

## License

MIT
