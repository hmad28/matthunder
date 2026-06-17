"""
matthunder_banner.py — generate stylized MATTHUNDER banner as PNG for Telegram.

Uses pyfiglet for ASCII + PIL to render with proper monospace spacing.
Cached on first call. Telegram photo doesn't suffer from text-rendering
issues that affect monospace markdown.
"""

import io
import os
from pathlib import Path

import pyfiglet
from PIL import Image, ImageDraw, ImageFont


CACHE_PATH = Path(__file__).resolve().parent / "bot_logs" / "matthunder_banner.png"
CACHE_PATH.parent.mkdir(exist_ok=True)

# Try a few fonts in order (Windows ships Consolas; Linux often DejaVu)
FONT_CANDIDATES = [
    r"C:\Windows\Fonts\consola.ttf",
    r"C:\Windows\Fonts\cour.ttf",
    r"C:\Windows\Fonts\consolab.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
    "/System/Library/Fonts/Menlo.ttc",
]


def _load_font(size: int):
    for path in FONT_CANDIDATES:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size=size)
            except Exception:
                continue
    return ImageFont.load_default()


def _render_ascii(text: str = "MATTHUNDER", font: str = "slant") -> tuple[str, int, int]:
    """Render text as ASCII art. Returns (ascii_text, max_line_len, line_count)."""
    out = pyfiglet.Figlet(font=font, width=200).renderText(text)
    # Strip trailing blank lines
    lines = out.rstrip("\n").split("\n")
    max_len = max(len(line) for line in lines) if lines else 0
    return "\n".join(lines), max_len, len(lines)


def build_banner(
    text: str = "MATTHUNDER",
    subtitle: str = "RECON & VULN BOT",
    figlet_font: str = "mini",
    char_size: int = 12,
    bg_color=(17, 24, 39),     # dark slate
    fg_color=(220, 38, 38),    # red accent (matthunder red)
    sub_color=(180, 200, 220),  # light gray
    pad: int = 16,
) -> bytes:
    """Render banner as PNG bytes. Optimized for Telegram mobile (~340px wide)."""
    ascii_text, max_len, line_count = _render_ascii(text, figlet_font)
    font = _load_font(char_size)
    sub_font = _load_font(int(char_size * 0.7))

    bbox = font.getbbox("M")
    char_w = bbox[2] - bbox[0]
    line_h = int(char_size * 1.15)

    img_w = int(char_w * max_len) + pad * 2
    img_h = line_h * line_count + pad * 2 + int(char_size * 1.8)

    img = Image.new("RGB", (img_w, img_h), bg_color)
    draw = ImageDraw.Draw(img)

    y = pad
    for line in ascii_text.split("\n"):
        if not line.strip():
            y += line_h
            continue
        draw.text((pad, y), line, fill=fg_color, font=font)
        y += line_h

    if subtitle:
        sub_bbox = sub_font.getbbox(subtitle)
        sub_w = sub_bbox[2] - sub_bbox[0]
        sub_x = (img_w - sub_w) // 2
        sub_y = y + int(char_size * 0.3)
        draw.text((sub_x, sub_y), subtitle, fill=sub_color, font=sub_font)

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def get_banner_bytes(use_cache: bool = True) -> bytes:
    """Return banner PNG bytes.

    Bypasses Telegram client-side photo cache by adding a single transparent
    pixel that varies per call (visible to PIL hash but not to user). This
    forces a new file_id per send.
    """
    import time
    if use_cache and CACHE_PATH.exists():
        try:
            if time_age_ok(CACHE_PATH, max_age_days=30):
                data = CACHE_PATH.read_bytes()
                return _jitter_pixels(data)
        except Exception:
            pass
    data = build_banner()
    try:
        CACHE_PATH.write_bytes(data)
    except Exception:
        pass
    return _jitter_pixels(data)


def _jitter_pixels(png_bytes: bytes) -> bytes:
    """Add a per-call-unique invisible pixel so the PNG byte hash differs and
    Telegram treats each send as a new file (no stale client-side cache).
    """
    try:
        from PIL import Image
        import io
        import time
        img = Image.open(io.BytesIO(png_bytes)).convert("RGBA")
        w, h = img.size
        # Stamp an invisible-near-bg pixel at the corner with a per-call value
        seed = int(time.time() * 1_000_000) & 0xFF
        # Encode seed in alpha channel: keep alpha 255 (fully opaque) so image
        # looks identical, but encode seed in R channel with a +/-1 shift that's
        # imperceptible against the dark slate background (#111827)
        r = (17 + (seed & 1)) & 0xFF  # 17 or 18 — visually identical
        img.putpixel((w-1, h-1), (r, 24, 39, 255))
        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        return buf.getvalue()
    except Exception:
        return png_bytes


def time_age_ok(path: Path, max_age_days: int = 30) -> bool:
    import time
    try:
        age = time.time() - path.stat().st_mtime
        return age < max_age_days * 86400
    except Exception:
        return False
