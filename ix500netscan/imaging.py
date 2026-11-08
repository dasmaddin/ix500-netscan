"""Blank page detection and lossless JPEG-to-PDF output."""
from __future__ import annotations

import io
import os
import time

import img2pdf
from PIL import Image, ImageFilter

SAMPLE_WIDTH = 400      # downscale before analysis
MARGIN = 0.06           # ignore borders (paper edges, shadows)
INK_DELTA = 60          # grey levels darker than the background that count as ink


def ink_ratio(jpeg: bytes) -> float:
    """Share of pixels that differ clearly from the paper background."""
    with Image.open(io.BytesIO(jpeg)) as im:
        im.draft("L", (SAMPLE_WIDTH * 2, SAMPLE_WIDTH * 3))   # fast JPEG downscale
        g = im.convert("L")
    w, h = g.size
    if w > SAMPLE_WIDTH:
        g = g.resize((SAMPLE_WIDTH, max(1, h * SAMPLE_WIDTH // w)))
        w, h = g.size
    mx, my = int(w * MARGIN), int(h * MARGIN)
    g = g.crop((mx, my, w - mx, h - my)).filter(ImageFilter.MedianFilter(3))
    hist = g.histogram()
    total = sum(hist)
    # background = brightest level that holds a meaningful share of pixels
    acc, background = 0, 255
    for level in range(255, -1, -1):
        acc += hist[level]
        if acc >= total * 0.5:
            background = level
            break
    cutoff = max(0, background - INK_DELTA)
    ink = sum(hist[:cutoff])
    return ink / total if total else 0.0


def is_blank(jpeg: bytes, threshold: float) -> bool:
    return ink_ratio(jpeg) < threshold


def filter_blank(pages: list[bytes], threshold: float) -> list[bytes]:
    """Drop blank pages; if everything looks blank, keep the first page."""
    kept = [p for p in pages if not is_blank(p, threshold)]
    if not kept and pages:
        kept = pages[:1]
    return kept


def unique_path(directory: str, template: str, when: float | None = None) -> str:
    name = time.strftime(template, time.localtime(when))
    base, ext = os.path.splitext(name)
    path = os.path.join(directory, name)
    n = 2
    while os.path.exists(path):
        path = os.path.join(directory, f"{base}_{n}{ext}")
        n += 1
    return path


def write_pdf(pages: list[bytes], directory: str, template: str, mode: int = 0o644) -> str:
    """Write pages as one PDF atomically (hidden temp file, then rename)."""
    if not pages:
        raise ValueError("no pages")
    target = unique_path(directory, template)
    tmp = os.path.join(directory, f".{os.path.basename(target)}.part")
    data = img2pdf.convert(pages)
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, target)
    return target
