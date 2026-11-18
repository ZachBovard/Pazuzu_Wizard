"""A small QR code maker, so a one-time code or a phone's VPN settings can be shown as a picture
without sending anything anywhere or needing another package.

Byte mode only, error correction L or M, versions 1 to 14 (up to 461 bytes at L). Returns a grid of
dark and light squares, or the same drawn as an SVG. It is checked in the tests by reading its own
pictures back with a real decoder.
"""

from __future__ import annotations

# (data codewords in all, error-correction codewords per block, ((blocks, data codewords each), ...))
_BLOCKS = {
    "L": {1: (19, 7, ((1, 19),)), 2: (34, 10, ((1, 34),)), 3: (55, 15, ((1, 55),)),
          4: (80, 20, ((1, 80),)), 5: (108, 26, ((1, 108),)), 6: (136, 18, ((2, 68),)),
          7: (156, 20, ((2, 78),)), 8: (194, 24, ((2, 97),)), 9: (232, 30, ((2, 116),)),
          10: (274, 18, ((2, 68), (2, 69))), 11: (324, 20, ((4, 81),)),
          12: (370, 24, ((2, 92), (2, 93))), 13: (428, 26, ((4, 107),)),
          14: (461, 30, ((3, 115), (1, 116)))},
    "M": {1: (16, 10, ((1, 16),)), 2: (28, 16, ((1, 28),)), 3: (44, 26, ((1, 44),)),
          4: (64, 18, ((2, 32),)), 5: (86, 24, ((2, 43),)), 6: (108, 16, ((4, 27),)),
          7: (124, 18, ((4, 31),)), 8: (154, 22, ((2, 38), (2, 39))),
          9: (182, 22, ((3, 36), (2, 37))), 10: (216, 26, ((4, 43), (1, 44))),
          11: (254, 30, ((1, 50), (4, 51))), 12: (290, 22, ((6, 36), (2, 37))),
          13: (334, 22, ((8, 37), (1, 38))), 14: (365, 24, ((4, 40), (5, 41)))},
}
_FORMAT_BITS = {"L": 1, "M": 0}
_ALIGN = {2: (6, 18), 3: (6, 22), 4: (6, 26), 5: (6, 30), 6: (6, 34), 7: (6, 22, 38),
          8: (6, 24, 42), 9: (6, 26, 46), 10: (6, 28, 50), 11: (6, 30, 54), 12: (6, 32, 58),
          13: (6, 34, 62), 14: (6, 26, 46, 66)}


class QrError(ValueError):
    pass


def _capacity_bytes(version: int, ecl: str) -> int:
    bits = _BLOCKS[ecl][version][0] * 8 - 4 - (8 if version < 10 else 16)
    return bits // 8


def _pick_version(n: int, ecl: str) -> int:
    for v in range(1, 15):
        if n <= _capacity_bytes(v, ecl):
            return v
    raise QrError("That is too long for a code this app can draw.")


# -- Reed-Solomon over GF(256), polynomial 0x11D
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a: int, b: int) -> int:
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _generator(degree: int) -> list[int]:
    poly = [1]
    for i in range(degree):
        nxt = [0] * (len(poly) + 1)
        for j, c in enumerate(poly):
            nxt[j] ^= c
            nxt[j + 1] ^= _mul(c, _EXP[i])
        poly = nxt
    return poly


def _remainder(data: list[int], degree: int) -> list[int]:
    gen = _generator(degree)
    rem = [0] * degree
    for byte in data:
        factor = byte ^ rem[0]
        rem = rem[1:] + [0]
        for i in range(degree):
            rem[i] ^= _mul(gen[i + 1], factor)
    return rem


def _codewords(data: bytes, version: int, ecl: str) -> list[int]:
    total, ec_len, groups = _BLOCKS[ecl][version]
    bits: list[int] = []

    def put(value: int, count: int) -> None:
        for i in range(count - 1, -1, -1):
            bits.append((value >> i) & 1)

    put(0b0100, 4)
    put(len(data), 8 if version < 10 else 16)
    for byte in data:
        put(byte, 8)
    room = total * 8
    put(0, min(4, room - len(bits)))
    while len(bits) % 8:
        bits.append(0)
    words = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = (0xEC, 0x11)
    while len(words) < total:
        words.append(pad[(len(words) - len(bits) // 8) % 2])
    blocks, at = [], 0
    for count, size in groups:
        for _ in range(count):
            blocks.append(words[at:at + size])
            at += size
    ecs = [_remainder(b, ec_len) for b in blocks]
    out: list[int] = []
    for i in range(max(len(b) for b in blocks)):
        out.extend(b[i] for b in blocks if i < len(b))
    for i in range(ec_len):
        out.extend(e[i] for e in ecs)
    return out


def _format_bits(ecl: str, mask: int) -> int:
    data = (_FORMAT_BITS[ecl] << 3) | mask
    rem = data << 10
    for i in range(14, 9, -1):
        if rem & (1 << i):
            rem ^= 0x537 << (i - 10)
    return ((data << 10) | rem) ^ 0x5412


def _version_bits(version: int) -> int:
    rem = version << 12
    for i in range(17, 11, -1):
        if rem & (1 << i):
            rem ^= 0x1F25 << (i - 12)
    return (version << 12) | rem


_MASKS = (
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
)


def _build(version: int, ecl: str, words: list[int], mask: int) -> list[list[bool]]:
    n = version * 4 + 17
    grid = [[False] * n for _ in range(n)]
    fixed = [[False] * n for _ in range(n)]

    def setf(r: int, c: int, dark: bool) -> None:
        grid[r][c] = dark
        fixed[r][c] = True

    def finder(r0: int, c0: int) -> None:
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                r, c = r0 + dr, c0 + dc
                if 0 <= r < n and 0 <= c < n:
                    ring = max(abs(dr - 3), abs(dc - 3))
                    setf(r, c, ring not in (2, 4) and ring <= 3)

    finder(0, 0)
    finder(0, n - 7)
    finder(n - 7, 0)
    pos = _ALIGN.get(version, ())
    for r in pos:
        for c in pos:
            if (r, c) in ((6, 6), (6, pos[-1]), (pos[-1], 6)):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    setf(r + dr, c + dc, max(abs(dr), abs(dc)) != 1)
    for i in range(8, n - 8):
        setf(6, i, i % 2 == 0)
        setf(i, 6, i % 2 == 0)
    # format areas are reserved now and filled below
    for i in range(9):
        fixed[8][i] = fixed[i][8] = True
    for i in range(8):
        fixed[8][n - 1 - i] = fixed[n - 1 - i][8] = True
    setf(n - 8, 8, True)                      # the always-dark module
    if version >= 7:
        vb = _version_bits(version)
        for i in range(18):
            dark = bool((vb >> i) & 1)
            setf(i // 3, n - 11 + i % 3, dark)
            setf(n - 11 + i % 3, i // 3, dark)
    # data, in the zig-zag order
    bits = [(w >> k) & 1 for w in words for k in range(7, -1, -1)]
    at, up, c = 0, True, n - 1
    while c > 0:
        if c == 6:
            c -= 1
        rows = range(n - 1, -1, -1) if up else range(n)
        for r in rows:
            for cc in (c, c - 1):
                if not fixed[r][cc]:
                    dark = bool(bits[at]) if at < len(bits) else False
                    at += 1
                    grid[r][cc] = dark ^ _MASKS[mask](r, cc)
        up = not up
        c -= 2
    fmt = _format_bits(ecl, mask)

    def bit(i: int) -> bool:
        return bool((fmt >> i) & 1)

    for i in range(6):
        grid[i][8] = bit(i)
    grid[7][8] = bit(6)
    grid[8][8] = bit(7)
    grid[8][7] = bit(8)
    for i in range(9, 15):
        grid[8][14 - i] = bit(i)
    for i in range(8):
        grid[8][n - 1 - i] = bit(i)
    for i in range(8, 15):
        grid[n - 15 + i][8] = bit(i)
    return grid


def _penalty(g: list[list[bool]]) -> int:
    n = len(g)
    score = 0
    for lines in (g, [list(col) for col in zip(*g)]):
        for row in lines:
            run, prev = 1, row[0]
            for v in row[1:]:
                if v == prev:
                    run += 1
                else:
                    score += run - 2 if run >= 5 else 0
                    run, prev = 1, v
            score += run - 2 if run >= 5 else 0
            s = "".join("1" if v else "0" for v in row)
            score += 40 * (s.count("10111010000") + s.count("00001011101"))
    for r in range(n - 1):
        for c in range(n - 1):
            if g[r][c] == g[r][c + 1] == g[r + 1][c] == g[r + 1][c + 1]:
                score += 3
    dark = sum(v for row in g for v in row)
    score += 10 * (abs(dark * 20 - n * n * 10) // (n * n))
    return score


def encode(text: str, ecl: str = "M") -> list[list[bool]]:
    if ecl not in _BLOCKS:
        raise QrError("Only error-correction levels L and M are drawn.")
    data = text.encode("utf-8")
    version = _pick_version(len(data), ecl)
    words = _codewords(data, version, ecl)
    best = min((_build(version, ecl, words, m) for m in range(8)), key=_penalty)
    return best


def svg(grid: list[list[bool]], border: int = 4, scale: int = 6, label: str = "QR code") -> str:
    n = len(grid)
    size = (n + border * 2) * scale
    rects = []
    for r, row in enumerate(grid):
        c = 0
        while c < n:
            if row[c]:
                start = c
                while c < n and row[c]:
                    c += 1
                rects.append(f"M{(start + border) * scale},{(r + border) * scale}h{(c - start) * scale}v{scale}h-{(c - start) * scale}z")
            else:
                c += 1
    safe = label.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 {size} {size}" '
            f'role="img" aria-label="{safe}"><rect width="{size}" height="{size}" fill="#fff"/>'
            f'<path d="{"".join(rects)}" fill="#000"/></svg>')
