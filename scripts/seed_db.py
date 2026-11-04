"""Fill the demo database, so the dashboard has content on first open."""
from __future__ import annotations

import json
import logging

from alertlens.config import ROOT
from alertlens.memory import store as db
from alertlens.pipeline.service import analyze_batch, hero_alerts, load_samples

log = logging.getLogger(__name__)
BENCHMARK_SHARE = 80


def seed(db_path: str | None = None, benchmark_share: int = BENCHMARK_SHARE) -> dict:
    from alertlens.pipeline.orchestrator import Options

    alerts = hero_alerts()
    alerts += [a for name, a in load_samples().items() if not name.startswith("hero")]
    bench = ROOT / "data" / "benchmark" / "alerts.jsonl"
    if bench.exists():
        alerts += [json.loads(line) for line in bench.read_text().splitlines()[:benchmark_share]]
    analyze_batch(alerts, Options(db_path=db_path))
    with db.db(db_path) as conn:
        return db.kpis(conn)


def ensure_seeded(db_path: str | None = None) -> None:
    with db.db(db_path) as conn:
        empty = db.kpis(conn)["alerts"] == 0
    if empty:
        seed(db_path)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    with db.db() as conn:
        if db.kpis(conn)["alerts"]:
            log.info("Database already seeded: %s", db.kpis(conn))
            return
    log.info("Seeded: %s", seed())


if __name__ == "__main__":
    main()
