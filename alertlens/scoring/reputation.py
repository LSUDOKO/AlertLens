"""Synthetic reputation data. All addresses come from reserved documentation ranges."""
BAD_IPS = frozenset({"203.0.113.45", "203.0.113.46", "203.0.113.66", "198.51.100.77", "198.51.100.88", "192.0.2.13"})
APPROVED_SCANNERS = frozenset({"198.51.100.10", "198.51.100.11"})
KNOWN_BAD_HASHES = frozenset({"a" * 64, "b" * 64, "c" * 64})
