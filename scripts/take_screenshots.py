#!/usr/bin/env python3
"""Generate PNG screenshots of every Sentinel TUI tab."""
from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path

OUT = Path("docs/screenshots")


async def generate() -> None:
    from sentinel.tui.app import SentinelApp  # noqa: PLC0415

    app = SentinelApp()
    async with app.run_test(headless=True, size=(160, 48)) as pilot:
        # Let the initial scan complete
        await pilot.pause(4.0)

        tabs = [
            ("1", "overview"),
            ("2", "apps"),
            ("3", "network"),
            ("4", "findings"),
            ("5", "search"),
            ("6", "users"),
            ("7", "resources"),
        ]
        for key, name in tabs:
            await pilot.press(key)
            await pilot.pause(0.4)
            svg_path = OUT / f"{name}.svg"
            app.save_screenshot(str(svg_path))
            print(f"  saved {svg_path}")


def svg_to_png(svg_path: Path) -> Path:
    png_path = svg_path.with_suffix(".png")
    try:
        subprocess.run(
            [
                "rsvg-convert",
                "--width", "1280",
                "--keep-aspect-ratio",
                "-o", str(png_path),
                str(svg_path),
            ],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        print(f"  rsvg-convert failed for {svg_path}: {exc.stderr.decode()}", file=sys.stderr)
        return svg_path
    svg_path.unlink()  # remove SVG after successful conversion
    return png_path


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    print("Launching Sentinel TUI and capturing screenshots…")
    asyncio.run(generate())
    print("Converting SVG → PNG…")
    for svg in sorted(OUT.glob("*.svg")):
        result = svg_to_png(svg)
        print(f"  → {result}")
    print(f"Done. Screenshots in {OUT}/")


if __name__ == "__main__":
    main()
