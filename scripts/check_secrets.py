"""`make check-secrets`: a simple regex scan of tracked and new files for anything key-shaped."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PATTERNS = {
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "AWS key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "API key": re.compile(r"\b(sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,}|gsk_[A-Za-z0-9]{30,})\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "assigned secret": re.compile(r"(?i)\b(api[_-]?key|secret|password|token)\b\s*[:=]\s*['\"][A-Za-z0-9/+_-]{16,}['\"]"),
}


def scan(paths: list[Path]) -> list[str]:
    hits = []
    for path in paths:
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for name, pattern in PATTERNS.items():
            for m in pattern.finditer(text):
                hits.append(f"{path}:{text[:m.start()].count(chr(10)) + 1}: {name}")
    return hits


def main() -> int:
    out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"], capture_output=True, text=True, check=True)
    hits = scan([Path(p) for p in out.stdout.splitlines() if Path(p).is_file()])
    for hit in hits:
        sys.stdout.write(hit + "\n")
    sys.stdout.write(f"Secret scan: {len(hits)} finding(s).\n")
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
