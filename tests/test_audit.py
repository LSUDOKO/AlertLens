import sqlite3

from alertlens.audit.chain import append, verify_chain
from alertlens.memory.store import connect


def filled(path):
    conn = connect(path)
    for i in range(5):
        append(conn, "t", "e", {"i": i})
    return conn


def test_clean_chain_verifies(tmp_path):
    assert verify_chain(filled(str(tmp_path / "a.db")))["ok"]


def test_empty_chain_verifies(tmp_path):
    assert verify_chain(connect(str(tmp_path / "a.db")))["checked"] == 0


def test_each_kind_of_edit_points_to_first_broken_row(tmp_path):
    for sql in ["UPDATE audit_log SET actor='evil' WHERE seq=3", "UPDATE audit_log SET event_type='x' WHERE seq=3",
                "UPDATE audit_log SET payload='{\"i\":99}' WHERE seq=3", "UPDATE audit_log SET ts='2000' WHERE seq=3",
                "UPDATE audit_log SET hash='00' WHERE seq=3", "DELETE FROM audit_log WHERE seq=3"]:
        path = str(tmp_path / f"{abs(hash(sql))}.db")
        conn = filled(path)
        conn.execute(sql)
        result = verify_chain(conn)
        assert not result["ok"] and result["first_broken_seq"] == 3, sql


def test_tail_truncation_is_a_known_limit(tmp_path):
    conn = filled(str(tmp_path / "a.db"))
    conn.execute("DELETE FROM audit_log WHERE seq=5")
    assert verify_chain(conn)["ok"]  # documented: tamper-evident, not tamper-proof


def test_separate_connections_share_one_chain(tmp_path):
    path = str(tmp_path / "a.db")
    a, b = connect(path), connect(path)
    append(a, "a", "e", {})
    append(b, "b", "e", {})
    append(a, "a", "e", {})
    assert verify_chain(sqlite3.connect(path))["checked"] == 3
