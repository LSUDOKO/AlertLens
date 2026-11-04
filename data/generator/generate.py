"""Seeded synthetic data generator.

    python -m data.generator.generate --seed 42 --n 2000 --out data/benchmark
    python -m data.generator.generate --samples
"""
from __future__ import annotations

import argparse
import json
import logging
import random
from pathlib import Path

from data.generator import injections as inj
from data.generator import scenarios as sc

log = logging.getLogger(__name__)
TRUTH_KEYS = {"label", "techniques", "scenario", "incident_group"}
# Injection only targets fields a given format really carries.
FORMATS_BY_CATEGORY = {
    "network": ["suricata", "suricata", "native", "wazuh"],
    "web": ["suricata", "native", "wazuh"],
    "authentication": ["wazuh", "sigma", "native"],
    "endpoint": ["wazuh", "sigma", "sigma", "native"],
    "cloud": ["native", "sigma"],
    "data": ["wazuh", "native", "suricata"],
}


def to_vendor(c: dict, fmt: str) -> dict:
    """Render a canonical alert in a vendor-like JSON shape."""
    if fmt == "native":
        return {**c, "source_format": "native"}
    if fmt == "wazuh":
        return {
            "id": c["alert_id"], "timestamp": c["timestamp"],
            "rule": {"id": c["rule_id"], "description": c["rule_name"], "level": c["rule_level"],
                     "groups": [c["category"]], "mitre": {"id": c.get("mitre_hint", [])}},
            "agent": {"name": c.get("host"), "criticality": c.get("asset_criticality")},
            "data": {k: c[k2] for k, k2 in [
                ("srcip", "src_ip"), ("dstip", "dst_ip"), ("srcuser", "user"), ("process", "process"),
                ("command", "command_line"), ("sha256", "file_hash"), ("url", "url"), ("geo", "geo_country"),
                ("device_known", "device_known"), ("geo_usual", "geo_usual"), ("event_count", "event_count"),
                ("user_privilege", "user_privilege"), ("http_user_agent", "user_agent"),
                ("bytes_out", "bytes_out"), ("target_user", "target_user"), ("domain", "domain"),
                ("outcome", "outcome"),
            ] if c.get(k2) is not None},
            "full_log": c.get("full_log"),
        }
    if fmt == "suricata":
        return {
            "flow_id": c["alert_id"], "timestamp": c["timestamp"], "event_type": "alert",
            "src_ip": c.get("src_ip"), "dest_ip": c.get("dst_ip"),
            "alert": {"signature_id": c["rule_id"], "signature": c["rule_name"], "level": c["rule_level"],
                      "category": c["category"], "metadata": {"mitre": c.get("mitre_hint", [])}},
            "http": {"url": c.get("url"), "http_user_agent": c.get("user_agent")},
            "dns": {"rrname": c.get("domain")},
            "host": c.get("host"), "user": c.get("user"), "process": c.get("process"),
            "command_line": c.get("command_line"), "full_log": c.get("full_log"),
            "context": {k: c.get(k) for k in ["asset_criticality", "user_privilege", "event_count", "device_known",
                                              "geo_country", "geo_usual", "bytes_out", "file_hash", "outcome",
                                              "target_user"]},
        }
    if fmt == "sigma":
        return {
            "sigma_rule": {"id": c["rule_id"], "title": c["rule_name"], "score": c["rule_level"],
                           "logsource": c["category"], "tags": c.get("mitre_hint", [])},
            "alert_id": c["alert_id"], "matched_at": c["timestamp"],
            "event": {k: v for k, v in c.items() if k not in {"rule_id", "rule_name", "rule_level", "category",
                                                              "mitre_hint", "alert_id", "timestamp"}},
        }
    raise ValueError(fmt)


# Clean log lines that use security vocabulary, so the false-positive rate is a real test.
HARD_NEGATIVE_LOGS = [
    "Operator closed ticket INC-4411 after the review", "Firewall rule 12 was reviewed and kept",
    "Login prompt timed out, user retried", "Ignored 3 duplicate events from the sensor",
    "Scheduled test of the backup restore passed", "Previous session expired, new session created",
    "Audit logs rotated by logrotate", "Password reset instructions were emailed to the user",
    "Severity mapping table reloaded by the service", "Marked mailbox as read by the sync job",
]


def _add_noise(r: random.Random, c: dict) -> None:
    """Missing fields, odd casing and extra vendor fields, as real feeds have."""
    if r.random() < 0.15:
        c["full_log"] = r.choice(HARD_NEGATIVE_LOGS)
    if r.random() < 0.05:
        c.pop(r.choice(["geo_country", "user_agent", "device_known"]), None)
    if r.random() < 0.05 and c.get("host"):
        c["host"] = c["host"].lower()
    if r.random() < 0.1:
        c["sensor_version"] = f"{r.randint(1, 4)}.{r.randint(0, 9)}"


def generate(seed: int, n: int, *, inject: bool = True, training_labels: bool = False) -> list[dict]:
    """Return records: {alert, clean_alert?, truth}. `training_labels` applies mislabels and label noise."""
    r = random.Random(seed)
    records: list[dict] = []
    group = 0
    mal_fns, mal_w = zip(*sc.MALICIOUS, strict=True)
    ben_fns, ben_w = zip(*sc.BENIGN, strict=True)
    while len(records) < n:
        group += 1
        if r.random() < 0.55:
            fn = r.choices(ben_fns, ben_w)[0]
        else:
            fn = r.choices(mal_fns, mal_w)[0]
        canon_list, label, techniques = fn(r)
        for c in canon_list:
            aid = f"ALR-{seed}-{len(records):06d}"
            c["alert_id"] = aid
            _add_noise(r, c)
            fmt = r.choice(FORMATS_BY_CATEGORY[c["category"]])
            truth_label = label
            if training_labels:
                if fn.__name__ in sc.MISLABELLED_IN_TRAINING:
                    truth_label = "benign"
                elif r.random() < 0.03:
                    truth_label = "benign" if label == "malicious" else "malicious"
            truth = {"alert_id": aid, "label": truth_label, "techniques": techniques, "scenario": fn.__name__,
                     "incident_group": f"G{seed}-{group}", "injection": None}
            rec = {"alert": None, "clean_alert": None, "truth": truth}
            rate = 0.25 if label == "malicious" else 0.05
            if inject and r.random() < rate:
                fields = [f for f in inj.TARGET_FIELDS if f in ("user_agent", "full_log", "rule_name") or c.get(f)]
                field = r.choice(fields)
                family, payload, heldout = inj.pick_payload(r)
                rec["clean_alert"] = to_vendor(c, fmt)
                dirty = {**c, field: inj.inject_value(c.get(field), payload)}
                rec["alert"] = to_vendor(dirty, fmt)
                truth["injection"] = {"family": family, "field_path": field, "payload": payload, "heldout": heldout}
            else:
                rec["alert"] = to_vendor(c, fmt)
            records.append(rec)
    return records[:n]


def resolved_cases(seed: int, n: int = 200) -> list[dict]:
    """Past incidents for retrieval, with resolutions written per scenario."""
    r = random.Random(seed + 1000)
    res = {
        "brute_force_success": ("Repeated failed logins followed by success on {u}", "Reset the password and enforced MFA",
                                "true_positive", ["T1110", "T1078"]),
        "credential_stuffing": ("Credential stuffing against {u} from many sources", "Blocked the sources, forced MFA",
                                "true_positive", ["T1110.004"]),
        "encoded_powershell": ("Encoded PowerShell execution with hidden window on {h}", "Isolated host, collected memory",
                               "true_positive", ["T1059.001", "T1027"]),
        "certutil_download": ("Certutil fetched a remote file on {h}", "Quarantined the file, reimaged host",
                              "true_positive", ["T1105"]),
        "new_local_admin": ("New local administrator created on {h}", "Removed account, reviewed admin changes",
                            "true_positive", ["T1136"]),
        "lateral_psexec": ("Remote service execution moved laterally from {h}", "Isolated both hosts, rotated credentials",
                           "true_positive", ["T1021.002"]),
        "night_exfil": ("Large outbound data transfer at night from {h}", "Blocked destination, opened data-loss review",
                        "true_positive", ["T1048"]),
        "dns_tunnel": ("Long random DNS subdomains from {h}", "Sinkholed the domain, isolated host",
                       "true_positive", ["T1071.004"]),
        "admin_late_known": ("Admin login outside business hours on a known device", "Confirmed with admin, closed",
                             "false_positive", ["T1078"]),
        "scheduled_backup": ("Large transfer by backup service to internal storage", "Matched backup schedule, closed",
                             "false_positive", []),
        "vuln_scanner": ("Port scan from the approved vulnerability scanner", "Confirmed scanner schedule, closed",
                         "false_positive", []),
        "mistyped_password": ("User mistyped password a few times", "Confirmed with user, closed",
                              "false_positive", []),
        "it_powershell": ("IT patching task using encoded PowerShell", "Matched change ticket, closed",
                          "false_positive", []),
    }
    keys = list(res)
    out = []
    for i in range(n):
        tmpl, resolution, outcome, techniques = res[r.choice(keys)]
        out.append({"case_id": f"CASE-{i + 100}", "summary": tmpl.format(u=r.choice(sc.USERS), h=r.choice(sc.HOSTS)[0]),
                    "resolution": resolution, "outcome": outcome, "techniques": techniques})
    return out


def write_benchmark(seed: int, n: int, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    recs = generate(seed, n)
    (out / "alerts.jsonl").write_text("\n".join(json.dumps(x["alert"], ensure_ascii=False) for x in recs) + "\n")
    (out / "ground_truth.jsonl").write_text("\n".join(json.dumps(x["truth"], ensure_ascii=False) for x in recs) + "\n")
    clean = [{"alert_id": x["truth"]["alert_id"], "alert": x["clean_alert"]} for x in recs if x["clean_alert"]]
    (out / "clean_counterparts.jsonl").write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in clean) + "\n")
    (out / "resolved_cases.jsonl").write_text("\n".join(json.dumps(x) for x in resolved_cases(seed)) + "\n")
    log.info("wrote %d alerts to %s", len(recs), out)


def write_samples(out: Path = Path("data/samples")) -> None:
    """The small committed demo set: hero, one per format, and each demo family."""
    (out / "hero").mkdir(parents=True, exist_ok=True)
    for a in sc.hero_alerts():
        (out / "hero" / f"{a['alert_id'].lower()}.json").write_text(json.dumps(a, indent=2, ensure_ascii=False))
    r = random.Random(7)
    picks = [("encoded_powershell", "wazuh"), ("certutil_download", "sigma"), ("dns_tunnel", "suricata"),
             ("night_exfil", "native"), ("lateral_psexec", "wazuh"), ("new_local_admin", "sigma"),
             ("admin_late_known", "native"), ("scheduled_backup", "wazuh"), ("vuln_scanner", "suricata"),
             ("mistyped_password", "sigma"), ("it_powershell", "native")]
    for i, (name, fmt) in enumerate(picks):
        canon = sc.ALL_SCENARIOS[name](r)[0][0]
        canon["alert_id"] = f"SAMPLE-{i + 1:02d}"
        (out / f"{i + 1:02d}_{name}_{fmt}.json").write_text(json.dumps(to_vendor(canon, fmt), indent=2))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--n", type=int, default=2000)
    p.add_argument("--out", type=Path, default=Path("data/benchmark"))
    p.add_argument("--samples", action="store_true")
    a = p.parse_args()
    if a.samples:
        write_samples()
    else:
        write_benchmark(a.seed, a.n, a.out)


if __name__ == "__main__":
    main()
