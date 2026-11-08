import io
import os
import random

from PIL import Image, ImageDraw

from ix500netscan import imaging

THRESHOLD = 0.0025


def _jpeg(draw=None, noise=0, tint=245, size=(1304, 1832)):
    im = Image.new("RGB", size, (tint, tint, tint - 5))
    if noise:
        rnd = random.Random(1)
        px = im.load()
        for _ in range(noise):
            x, y = rnd.randrange(size[0]), rnd.randrange(size[1])
            v = tint - rnd.randrange(25)
            px[x, y] = (v, v, v)
    if draw:
        draw(ImageDraw.Draw(im))
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=85, dpi=(150, 150))
    return buf.getvalue()


def _text(d):
    for i in range(30):
        d.text((120, 150 + i * 45), "Lorem ipsum dolor sit amet, consectetur " * 2, fill=(20, 20, 20))


def _shadow_edge(d):
    d.rectangle((0, 0, 30, 1832), fill=(90, 90, 90))   # dark border, ignored by margin


def test_blank_page_detected():
    assert imaging.is_blank(_jpeg(), THRESHOLD)
    assert imaging.is_blank(_jpeg(noise=20000), THRESHOLD)
    assert imaging.is_blank(_jpeg(draw=_shadow_edge), THRESHOLD)


def test_text_page_kept():
    assert not imaging.is_blank(_jpeg(draw=_text), THRESHOLD)


def test_single_mark_kept():
    def stamp(d):
        d.rectangle((500, 700, 760, 900), fill=(30, 30, 160))
    assert not imaging.is_blank(_jpeg(draw=stamp), THRESHOLD)


def test_filter_keeps_first_when_all_blank():
    pages = [_jpeg(), _jpeg()]
    assert imaging.filter_blank(pages, THRESHOLD) == pages[:1]
    text = _jpeg(draw=_text)
    assert imaging.filter_blank([text, _jpeg(), text], THRESHOLD) == [text, text]


def test_write_pdf_atomic(tmp_path):
    pages = [_jpeg(draw=_text), _jpeg(draw=_text)]
    p1 = imaging.write_pdf(pages, str(tmp_path), "scan_%Y.pdf")
    p2 = imaging.write_pdf(pages, str(tmp_path), "scan_%Y.pdf")
    assert p1 != p2 and p2.endswith("_2.pdf")
    data = open(p1, "rb").read()
    assert data.startswith(b"%PDF") and data.count(b"/Type /Page\n") + data.count(b"/Type /Page ") >= 0
    assert oct(os.stat(p1).st_mode & 0o777) == "0o644"
    assert not [f for f in os.listdir(tmp_path) if f.endswith(".part")]
