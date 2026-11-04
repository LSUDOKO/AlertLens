"""F17: hash-chained audit log. Tamper-evident, not tamper-proof: someone who can rewrite the whole
table and recompute every hash, or cut records off the end, is not detected without an external anchor."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

GENESIS = "0" * 64


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def _hash(prev_hash: str, record: dict) -> str:
    return hashlib.sha256((prev_hash + canonical(record)).encode()).hexdigest()


def append(conn: sqlite3.Connection, actor: str, event_type: str, payload: dict) -> int:
    """Add one record inside a write transaction, so concurrent writers cannot fork the chain."""
    in_tx = conn.in_transaction
    if not in_tx:
        conn.execute("BEGIN IMMEDIATE")
    row = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    seq, prev = (row[0] + 1, row[1]) if row else (1, GENESIS)
    body = canonical(payload)
    record = {"seq": seq, "ts": datetime.now(timezone.utc).isoformat(), "actor": actor, "event_type": event_type,
              "payload_hash": hashlib.sha256(body.encode()).hexdigest(), "prev_hash": prev}
    digest = _hash(prev, record)
    conn.execute("INSERT INTO audit_log(seq,ts,actor,event_type,payload,payload_hash,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?)",
                 (seq, record["ts"], actor, event_type, body, record["payload_hash"], prev, digest))
    if not in_tx:
        conn.commit()
    return seq


def verify_chain(conn: sqlite3.Connection) -> dict:
    """Walk the chain. Returns {ok, checked, first_broken_seq, reason}."""
    prev, expected_seq, checked = GENESIS, 1, 0
    for seq, ts, actor, event_type, payload, payload_hash, prev_hash, digest in conn.execute(
            "SELECT seq,ts,actor,event_type,payload,payload_hash,prev_hash,hash FROM audit_log ORDER BY seq"):
        def broken(reason):
            return {"ok": False, "checked": checked, "first_broken_seq": seq, "reason": reason}  # noqa: B023

        if seq != expected_seq:
            return {"ok": False, "checked": checked, "first_broken_seq": expected_seq, "reason": "missing record"}
        if hashlib.sha256(payload.encode()).hexdigest() != payload_hash:
            return broken("payload does not match its hash")
        if prev_hash != prev:
            return broken("link to the previous record is broken")
        record = {"seq": seq, "ts": ts, "actor": actor, "event_type": event_type, "payload_hash": payload_hash,
                  "prev_hash": prev_hash}
        if _hash(prev, record) != digest:
            return broken("record hash does not match")
        prev, expected_seq, checked = digest, seq + 1, checked + 1
    return {"ok": True, "checked": checked, "first_broken_seq": None, "reason": None}
