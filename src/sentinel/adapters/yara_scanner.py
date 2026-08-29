"""Optional YARA adapter — scans files for suspicious patterns.

If the `yara` package is not installed this module imports cleanly and all
scan calls return empty results.  Install yara-python to enable:

    pip install yara-python          # requires libyara (brew install yara)
    poetry install --extras deep
"""

from __future__ import annotations

from sentinel.log import get_logger

logger = get_logger("yara_scanner")

# ── built-in rules ─────────────────────────────────────────────────────────────

_BUILTIN_RULES = r"""
rule SuspiciousTempExecutable {
    meta:
        description = "Executable script located in a temporary directory"
    strings:
        $sh   = "#!/bin/sh"
        $bash = "#!/bin/bash"
        $py   = "#!/usr/bin/env python"
        $py3  = "#!/usr/bin/python3"
    condition:
        any of them
}

rule EicarTest {
    meta:
        description = "EICAR antivirus test string"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule EncodedPayload {
    meta:
        description = "Long base64-encoded string typical of obfuscated payloads"
    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
    condition:
        $b64
}

rule ReverseShell {
    meta:
        description = "Common reverse shell indicators"
    strings:
        $nc  = "nc -e /bin"
        $bsh = "/dev/tcp/"
        $bsh2 = "bash -i >&"
    condition:
        any of them
}
"""


class YaraScanner:
    """Wraps yara-python for file scanning. No-ops when yara is unavailable."""

    def __init__(self, rules_source: str = _BUILTIN_RULES) -> None:
        self._rules = None
        try:
            import yara  # type: ignore[import-not-found]

            self._rules = yara.compile(source=rules_source)
        except ImportError:
            pass
        except Exception as exc:
            logger.warning("YARA rule compilation failed: %s", exc)

    @property
    def available(self) -> bool:
        return self._rules is not None

    def scan_file(self, path: str) -> list[str]:
        """Return list of matching rule names. Empty list if YARA unavailable or no match."""
        if self._rules is None:
            return []
        try:
            matches = self._rules.match(path)
            return [m.rule for m in matches]
        except Exception as exc:
            logger.debug("YARA scan failed for %s: %s", path, exc)
            return []

    def scan_bytes(self, data: bytes) -> list[str]:
        """Scan raw bytes. Returns matching rule names."""
        if self._rules is None:
            return []
        try:
            matches = self._rules.match(data=data)
            return [m.rule for m in matches]
        except Exception as exc:
            logger.debug("YARA bytes scan failed: %s", exc)
            return []
