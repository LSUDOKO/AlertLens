"""The hash-chained log, integrity check and tamper demo."""
import sys
from pathlib import Path

# Streamlit Cloud does not put the repo root on the import path.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import sqlite3
import tempfile
from pathlib import Path

import streamlit as st

from alertlens.audit.chain import verify_chain
from alertlens.config import get_settings
from alertlens.pipeline import service
from ui.common import setup

setup("Audit log")
st.title("Audit log")
a, b = st.columns(2)
if a.button("Verify integrity", type="primary"):
    st.session_state["verify"] = service.audit_verify()
if b.button("Run tamper demo on a copy"):
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "copy.db"
        conn = sqlite3.connect(get_settings().db_path)
        with sqlite3.connect(copy) as out:
            conn.backup(out)
        conn.close()
        with sqlite3.connect(copy) as c:
            first = c.execute("SELECT MIN(seq) FROM audit_log").fetchone()[0]
            c.execute("UPDATE audit_log SET actor='attacker' WHERE seq=?", (first,))
            c.commit()
            st.session_state["tamper"] = verify_chain(c)
        c.close()
if v := st.session_state.get("verify"):
    if v["ok"]:
        st.success(f"Chain intact. Checked {v['checked']} records.")
    else:
        st.error(f"Chain broken at record {v['first_broken_seq']}: {v['reason']}.")
if t := st.session_state.get("tamper"):
    st.error(f"Tamper demo: changing one row in a copy broke the chain at record {t['first_broken_seq']}: {t['reason']}. "
             "The real log was not changed.")
st.dataframe([{"Seq": e["seq"], "Time": e["ts"][:19], "Actor": e["actor"], "Event": e["event_type"], "Hash": e["hash"][:16]}
              for e in service.audit_entries(300)], hide_index=True, width="stretch")
