# ix500-netscan

Scan from a Fujitsu/PFU **ScanSnap iX500 over Wi-Fi straight into a folder** on Linux, without
ScanSnap Cloud and without ScanSnap Home or ScanSnap Manager running on a Windows or Mac computer.
Press the scan button and a PDF appears in a directory of your choice, for example the consume
folder of [Paperless-ngx](https://docs.paperless-ngx.com/).

The service impersonates ScanSnap Home toward the scanner and speaks the iX500's own network
protocol (reverse engineered for interoperability, see [docs/PROTOCOL.md](docs/PROTOCOL.md)). It is
a small Python program, meant to run in Docker on an always-on Linux machine.

## Tested with

- ScanSnap iX500, firmware `0U00`. Nothing else.

Other Wi-Fi models (iX1500, iX1600, S1300i, ...) are untested and may use a different protocol.
Reports are welcome, support is not promised.

## Features

- Reacts to the scanner's **scan button**; scans every sheet in the feeder, front and back
- One **PDF per button press**, JPEG pages embedded losslessly (300 dpi, colour)
- **Blank page removal** (empty backs of single-sided sheets)
- Atomic writes: files appear complete, never half-written
- **Mode switch** `local` / `cloud` via a small JSON API: release the scanner so ScanSnap Cloud or
  ScanSnap Home can use it again
- Reconnects on its own when the scanner sleeps, is switched off or drops off Wi-Fi

## Requirements

- Linux host in the same network as the scanner, Docker with host networking
  (or Python 3.12 and `pip install -r requirements.txt`)
- UDP port 55265 reachable on the host (the scanner sends button events there)
- A one-time setup of the scanner with PFU's software, see below

## Preparing the scanner

The service cannot do the initial setup. You need a Windows or Mac computer with PFU's software
once.

1. **Connect the scanner to Wi-Fi** with PFU's tools (the Wi-Fi setup of ScanSnap Home or
   ScanSnap Manager). Note the scanner's IP address; a DHCP reservation in your router helps.
2. **Pair it once with a computer** using ScanSnap Home or ScanSnap Manager. This stores a host ID
   on the scanner. The scanner only accepts reservations that carry the host ID of a computer it
   was paired with.
3. **Start the service** (see Quick start). With `HOST_ID=auto` (the default) it adopts the host ID
   the scanner advertises, so the paired computer does not have to be online afterwards.
4. **Switch between local and cloud** with the API (`POST /api/mode`). In `local` mode the service
   keeps the scanner reserved; in `cloud` mode it releases it.

A scanner that is set up for ScanSnap Cloud does not need to be changed. While the service runs in
`local` mode, its reservation takes precedence and scans go to this service. Switching to `cloud`
mode or stopping the service releases the scanner, which then returns to ScanSnap Cloud after a
short while.

Untested: a scanner that was set up only via the ScanSnap Cloud app and never paired with a
computer. It probably advertises no host ID, in which case reservations are rejected (see below).

**Error `0xFFFFFFF9` (-7)**: the scanner rejected the reservation because the host ID is not the
one of a paired computer. Pair the scanner once with ScanSnap Home or ScanSnap Manager (step 2),
then restart the service. If you set `HOST_ID` manually, go back to `auto`.

## Quick start (Docker)

A prebuilt multi-arch image (`linux/amd64`, `linux/arm64`) is published as
`ghcr.io/dasmaddin/ix500-netscan:latest`. The arm64 image is built but untested.

```sh
mkdir ix500-netscan && cd ix500-netscan
curl -fsSLO https://raw.githubusercontent.com/dasmaddin/ix500-netscan/main/docker-compose.example.yml
curl -fsSL -o .env https://raw.githubusercontent.com/dasmaddin/ix500-netscan/main/.env.example
mv docker-compose.example.yml docker-compose.yml   # adjust the output volume
$EDITOR .env                                       # set IX500_PASSWORD, optionally IX500_HOST
docker compose up -d
docker compose logs -f
```

Find your scanner first:

```sh
docker compose run --rm ix500-netscan probe
# 192.168.1.50  iX500-A0XX000000  ScanSnap iX500  state=free  host_id=...
```

`probe` only searches the network; it does not reserve the scanner. It prints a note if the host
ID looks like it would be rejected.

To build the image yourself instead, clone the repository, replace `image:` with `build: .` in
`docker-compose.yml` (the example contains the line) and run `docker compose up -d --build`.

**Host networking is required.** The scanner sends button events to the host's IP address
(UDP 55265) and identifies the computer by the MAC address of its network interface. With Docker's
default bridge network it would see the container's address instead.

Files are written as the container user (UID/GID 1000 by default; when building yourself, change
this with the build args `UID`/`GID`). Make sure that user can write to the output directory.

## Configuration

Environment variables, usually set in `.env`:

| Variable | Default | Meaning |
|---|---|---|
| `IX500_HOST` | *(empty)* | Scanner IP; empty = discover by broadcast |
| `IX500_PASSWORD` | *(empty)* | Scanner password. Factory default per PFU: last 4 digits of the serial number |
| `IX500_IFACE` | *(auto)* | Local interface toward the scanner |
| `HOST_ID` | `auto` | Host ID sent when reserving; `auto` = the one the scanner advertises |
| `OUTPUT_DIR` | `/output` | Where PDFs go |
| `FILENAME_TEMPLATE` | `scan_%Y%m%d_%H%M%S.pdf` | `strftime` pattern; `_2`, `_3` ... on collision |
| `BLANK_PAGE_DETECTION` | `on` | Drop blank pages |
| `BLANK_PAGE_THRESHOLD` | `0.0025` | Share of ink pixels below which a page counts as blank |
| `FILE_MODE` | `0644` | Permissions of written PDFs |
| `DEFAULT_MODE` | `local` | Mode on first start (`local` or `cloud`); later the last chosen mode is kept |
| `API_BIND` / `API_PORT` | `127.0.0.1` / `8099` | JSON API |
| `STATE_DIR` | `/state` | Persists the chosen mode |
| `LOG_LEVEL` | `INFO` | `DEBUG` also shows repeated connection failures |

When the scanner is switched off, the service logs one warning and keeps retrying quietly; it logs
"scanner reachable again" when the scanner is back.

## API

```
GET  /health            {"ok": true}
GET  /api/status        mode, scanner state, current problem, last scan, recent errors
POST /api/mode          {"mode": "local"} or {"mode": "cloud"}
```

Example:

```sh
curl -s localhost:8099/api/status
curl -s -X POST -d '{"mode": "cloud"}' localhost:8099/api/mode
```

`scanner.state` is `free`, `reserved`, `unreachable` or `unknown`. `problem` describes the current
streak of failures (`unreachable`, `host_id_rejected` or an error message) or is `null`.

The API has **no authentication**. It binds to `127.0.0.1` by default. If you expose it, put a
reverse proxy with access control in front of it.

## How it works

1. Find the scanner (UDP 52217) and **reserve** it (TCP 53219). While reserved, the scanner is in
   "computer mode" and sends button presses to this host.
2. Keep the reservation alive with a datagram every ~12 s. Without it the scanner returns to
   being free (and to ScanSnap Cloud, if configured) after about 45 seconds.
3. Keep a command connection open (TCP 53218), wait for the button, then feed the sheets and read
   JPEG images page by page.
4. `cloud` mode simply releases the reservation.

Scan settings are fixed to what ScanSnap Home's "auto" profile sends: colour, 300 dpi, duplex,
JPEG. Other settings are not implemented.

## Security

Treat the iX500 as an insecure device.

- Its network functions are protected only by a short, weak password. The factory default is the
  last 4 digits of the serial number, and the scanner announces its serial number to anyone on the
  network who searches for it. The factory password is therefore effectively public.
- Set your own password with PFU's tools and put it in `IX500_PASSWORD`.
- Keep the scanner in a network without untrusted devices (for example a separate VLAN or IoT
  network that the host running this service can reach).
- Never expose the scanner's ports to the internet.
- The password is sent only lightly obfuscated, not encrypted. Anyone who can capture traffic
  between this service and the scanner can recover it.

## Support and contributing

Built for my own use. No support promised. Issues with ideas, tips and bug reports are welcome, so
are pull requests and forks.

For a bug report, include the scanner model, firmware version, the output of `probe` (with the
serial number redacted) and the relevant log lines.

Run the tests with:

```sh
pip install -r requirements.txt pytest
pytest
```

## Disclaimer

This project is not affiliated with, endorsed by or supported by PFU Limited or Fujitsu. ScanSnap
and the product names mentioned are trademarks of PFU Limited. The protocol was analysed solely to
achieve interoperability with the owner's own device. The project contains no PFU code, firmware
or other PFU material. Use at your own risk.

## License

[MIT](LICENSE)
