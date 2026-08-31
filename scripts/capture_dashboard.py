#!/usr/bin/env python3
"""Capture browser dashboard screenshots using Playwright."""
from __future__ import annotations

from pathlib import Path

OUT = Path("docs/screenshots")


def main() -> None:
    from playwright.sync_api import sync_playwright

    OUT.mkdir(parents=True, exist_ok=True)

    sections = [
        ("overview", "dashboard-overview.png"),
        ("network", "dashboard-network.png"),
        ("processes", "dashboard-processes.png"),
        ("findings", "dashboard-findings.png"),
        ("activity", "dashboard-activity.png"),
    ]

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto("http://localhost:7173/")
        page.wait_for_load_state("networkidle")

        for section, filename in sections:
            selector = f'div.nav-item[data-section="{section}"]'
            page.click(selector)
            page.wait_for_timeout(800)
            path = OUT / filename
            page.screenshot(path=str(path), full_page=False)
            print(f"  saved {path}")

        browser.close()
    print(f"Done. Screenshots in {OUT}/")


if __name__ == "__main__":
    main()
