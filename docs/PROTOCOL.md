# ScanSnap iX500 Wi-Fi protocol

Notes on the subset of the iX500 network protocol that ix500-netscan uses. Derived from observing
the traffic between the scanner and ScanSnap Home and from testing against a real iX500
(firmware reporting `0U00`). Fields marked *?* are not understood.

All integers are **big endian** unless noted.

## Ports

| Port | Proto | Direction | Purpose |
|---|---|---|---|
| 52217 | UDP | host → scanner | search, keep-alive |
| 53218 | TCP | host → scanner | scanner control: SCSI-like commands, image data |
| 53219 | TCP | host → scanner | app control: reserve, release, device info |
| 55265 | UDP | scanner → host | scan button pressed |

## Search and keep-alive (UDP 52217)

Request, 32 bytes:

| Off | Len | Content |
|---|---|---|
| 0x00 | 4 | keycode `VENS` |
| 0x04 | 4 | 0 = search, 1 = keep-alive |
| 0x08 | 4 | host IPv4 |
| 0x0C | 8 | host MAC + 2 zero bytes |
| 0x14 | 4 | `00 00 00 FF` |
| 0x18 | 2 | interface version `0x0010` |
| 0x1A | 6 | 0 |

Search answer, 132 bytes:

| Off | Len | Content |
|---|---|---|
| 0x00 | 4 | `VENS` |
| 0x08 | 8 | ? |
| 0x10 | 4 | scanner IPv4 |
| 0x14 | 4 | scanner-control port (53218) |
| 0x18 | 4 | app-control port (53219) |
| 0x1C | 8 | scanner MAC + 2 zero bytes |
| 0x24 | 4 | state; low byte `0x07` = free, `0x04` = reserved by a host |
| 0x28 | 64 | scanner name, NUL-terminated |
| 0x68 | 16 | model, space padded |
| 0x7C | 8 | host ID of the paired computer (6 bytes + 2 zero bytes) |

Keep-alive: send three keep-alive requests 500 ms apart every ~12.5 s. The answer is 12 bytes
(`VENS 80 01 00 00 00 00 00 00`). Without keep-alives a reservation expires after about 40–50 s.

## TCP framing

Every message in both directions starts with `u32 total length` (including itself) and the
keycode. Right after a TCP connect the scanner sends a 16-byte greeting
`00 00 00 10 VENS 00 00 00 00 00 00 00 00` (status 0 = OK).

## App control (TCP 53219)

One short-lived connection per request: connect, read greeting, send, read answer, close.
Command code is a u32 at 0x08.

| Code | Request | Purpose |
|---|---|---|
| 0x11 | 128 bytes | reserve |
| 0x12 | 32 bytes | release |
| 0x13 | 32 bytes | device info (answer: name at 0x10) |
| 0x30 | 32 bytes | Wi-Fi status |

Short requests (0x12, 0x13, 0x30): length, `VENS`, code, 0, host MAC (8 bytes), then zeros;
release carries u32 `1` at 0x18. Answers carry a u32 status at 0x08 (0 = OK).

### Reserve (0x11)

| Off | Len | Content |
|---|---|---|
| 0x00 | 4 | length `0x80` |
| 0x04 | 4 | `VENS` |
| 0x08 | 4 | `0x11` |
| 0x10 | 8 | host MAC + 2 zero bytes |
| 0x20 | 2 | interface version `0x0010` |
| 0x22 | 1 | `0x1E` (?) |
| 0x28 | 4 | 1 = password follows, 0 = none |
| 0x2C | 4 | host IPv4 |
| 0x30 | 4 | host UDP port for button events (55265) |
| 0x34 | 48 | encoded password, NUL padded |
| 0x64 | 4 | local date: u16 year, u8 month, u8 day |
| 0x68 | 4 | local time: u8 hour, minute, second, 0 |
| 0x6C | 8 | host ID (6 bytes + 2 zero bytes) |
| 0x74 | 4 | s32 UTC offset in seconds as (UTC − local), e.g. −3600 for CET |
| 0x78 | 8 | 0 |

Answer: 20 bytes, status at 0x08. Status `0xFFFFFFF9` (−7) is returned when the host ID is not
the one of a paired computer. The scanner advertises the accepted host ID in its search answer.

Password encoding (an obfuscation, not encryption): for each character `c` at position `i`
(at most 16), append the three decimal digits of `c + 11 + key[i]`, with
`key = "pFusCANsNapFiPfu"`.

## Scanner control (TCP 53218)

Command: 64-byte header followed by outgoing data.

| Off | Len | Content |
|---|---|---|
| 0x00 | 4 | length (0x40 + outgoing data) |
| 0x04 | 4 | `VENS` |
| 0x08 | 4 | 1 |
| 0x10 | 8 | host MAC + 2 zero bytes |
| 0x20 | 4 | CDB length |
| 0x24 | 4 | expected incoming data length |
| 0x28 | 4 | outgoing data length |
| 0x30 | 16 | CDB, zero padded |

Answer: 40-byte header (length, `VENS`, u32 transport status at 0x08, u32 SCSI status at 0x0C;
2 = check condition → REQUEST SENSE), then data.

| CDB | Name | Data |
|---|---|---|
| `12 00 00 00 60 00` | INQUIRY | in 0x60 |
| `c2 00 00 00 00 00 00 00 20 00` | get hardware status | in 0x20: byte 3 bit 7 = feeder empty, byte 4 bit 0 = button |
| `e6 00 01 00 00 00 00 04` | power info | in 4 |
| `d5 00 00 00 08 08` | start job | out 8 × 0, in 8 |
| `d6 00 00 00 00 00` | end job | – |
| `d8 00 00 00 00 00` | cancel | – |
| `e9 00 00 00 00 00 00 20 00 00` | set pre-read | out 0x20 |
| `d4 00 00 00 50 00` | set scan parameters | out 0x50 |
| `e0 00 00 00 00 00` | feed sheet | check condition + sense key 3, ASC/ASCQ 80/03 = feeder empty |
| `28 00 00 02 00 SS LL LL LL 00 NN 00` | read image | in LLLLLL; `SS` 0x00 front / 0x80 back, `NN` image number |
| `28 00 80 00 00 SS 00 00 20 00 00 00` | read image info | in 0x20 (width, height, dpi) |
| `03 00 00 00 12 00` | request sense | in 0x12 |

Parameter blocks used for colour, 300 dpi, duplex, JPEG are in
[`ix500netscan/protocol.py`](../ix500netscan/protocol.py) (`PREREAD_DATA`, `PARAMS_DATA`).

Image data: a read returns a 2-byte prefix (image number, 0) followed by one complete JPEG page.
The answer ends with check condition; the sense reports EOM + ILI (end of page). The scanner always
delivers front and back of every sheet.

### Batch sequence

```
(after reserving) INQUIRY, hardware status, start job, end job
poll hardware status every ~250 ms  /  or wait for the button datagram
on button: start job, power info, cancel, set pre-read, set parameters, start job
  while feed sheet succeeds:
    for front, back: read image, request sense (EOM), read image info
close the connection; on a new connection: end job; then reconnect and poll again
```

## Button event (UDP 55265, scanner → host)

48 bytes: length `0x30`, `VENS`, u32 code (1 = scan button), u32 0, u8 counter at 0x10. Each
event is sent three times 500 ms apart with the same counter. No answer is expected.
