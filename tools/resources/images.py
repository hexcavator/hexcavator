"""Writes the images resources.rc takes, into the directory given: icon.ico
(a 16x16 bitmap and a 32x32 PNG), arrow.cur (32x32, one bit, its hot spot
at 5,7), and stripes.bmp (8x4, 24 bits). All drawn here, so the test's
files are ours."""

import struct
import sys
import zlib
from pathlib import Path


def dib(width, height, bits, pixels, mask):
    """A bitmap as an icon or cursor holds it: its header (of twice its
    height: its image's and its mask's), its colors, its mask."""
    colors = b"" if bits > 8 else b"\x00\x00\x00\x00\xff\xff\xff\x00"
    header = struct.pack("<IiiHHIIiiII", 40, width, height * 2, 1, bits, 0, 0, 0, 0, 0, 0)
    return header + colors + pixels + mask


def png(width, height):
    """A PNG of a red-to-blue gradient, RGBA."""
    rows = b""
    for y in range(height):
        rows += b"\x00" + b"".join(bytes((255 - x * 8, 0, x * 8, 255)) for x in range(width))
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b"")


def directory(cursor, images):
    """An .ico or .cur file: its header, its entries, its images."""
    out = struct.pack("<HHH", 0, 2 if cursor else 1, len(images))
    offset = 6 + 16 * len(images)
    for (w, h, planes_or_x, bits_or_y, data) in images:
        out += struct.pack("<BBBBHHII", w % 256, h % 256, 0, 0, planes_or_x, bits_or_y, len(data), offset)
        offset += len(data)
    return out + b"".join(i[4] for i in images)


def main():
    out = Path(sys.argv[1])
    # The 16x16 icon: green, with a transparent corner.
    pixels = b"".join(b"\x20\xc0\x40\xff" for _ in range(16 * 16))
    mask = b"\x00\x00\x00\x00" * 15 + b"\xc0\x00\x00\x00"
    small = dib(16, 16, 32, pixels, mask)
    big = png(32, 32)
    (out / "icon.ico").write_bytes(directory(False, [(16, 16, 1, 32, small), (32, 32, 1, 32, big)]))
    # The cursor: a diagonal line (one bit; the mask, all opaque).
    rows = b"".join(struct.pack(">I", 1 << (31 - y)) for y in range(32))
    cursor = dib(32, 32, 1, rows, b"\x00" * 128)
    (out / "arrow.cur").write_bytes(directory(True, [(32, 32, 5, 7, cursor)]))
    # The bitmap: 8x4, 24 bits, rows of 24 bytes (no padding needed).
    pixels = b"".join(bytes((0, 0, 255) if (x + y) % 2 else (255, 255, 0)) for y in range(4) for x in range(8))
    info = struct.pack("<IiiHHIIiiII", 40, 8, 4, 1, 24, 0, len(pixels), 2835, 2835, 0, 0)
    (out / "stripes.bmp").write_bytes(struct.pack("<2sIHHI", b"BM", 14 + 40 + len(pixels), 0, 0, 54) + info + pixels)


main()
