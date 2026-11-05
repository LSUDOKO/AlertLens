"""Ordinary log sentences, used as negatives for the injection classifier.

They deliberately use words attackers also use (approved, reviewed, test, ignored, safe), so the classifier
has to learn more than "a sentence in a log is an attack".
"""
from __future__ import annotations

import random

ACTORS = ["the administrator", "the system account", "the backup service", "the scheduler", "the help desk", "the security team",
          "the identity provider", "the change management system", "the monitoring agent", "the deploy pipeline", "an operator",
          "the on-call engineer", "the patch manager", "the endpoint agent", "the audit service", "the mail gateway"]
PASSIVE = ["was approved by", "was reviewed by", "was restarted by", "was updated by", "was closed by", "was renewed by",
           "was installed by", "was removed by", "was tested by", "was scheduled by", "was ignored by", "was rotated by"]
THINGS = ["the change request", "the web server certificate", "the firewall rule set", "the nightly backup job", "the log rotation task",
          "the antivirus definition update", "the database connection pool", "the service account token", "the vpn configuration",
          "the disk cleanup task", "the password reset ticket", "the access review", "the monitoring test message", "the software inventory scan"]
STATES = ["completed successfully", "finished with no errors", "failed and will retry in 30 seconds", "timed out after 60 seconds",
          "started on schedule", "was skipped because nothing changed", "found no threats", "returned a warning", "is safe to rerun",
          "is expected to run again tomorrow", "was delayed by maintenance", "exceeded the 90 percent threshold"]
EVENTS = ["session opened for the user by the login service", "connection closed by the remote host after the idle timeout",
          "duplicate event ignored because the previous record had the same id", "user added to the finance group during onboarding",
          "this is a test message to confirm alert delivery", "please contact the help desk if you did not request this change",
          "new device enrolled by the employee from the corporate network", "policy applied to all hosts in the branch office",
          "retention rule removed old files from the archive folder", "login allowed because the device passed the compliance check",
          "routine maintenance is scheduled for this host on saturday night", "password reminder sent to the user by the portal"]


def benign_log_lines(seed: int, n: int = 500) -> list[str]:
    rng = random.Random(seed)
    lines = set(EVENTS)
    while len(lines) < n:
        form = rng.randrange(3)
        if form == 0:
            line = f"{rng.choice(THINGS)} {rng.choice(PASSIVE)} {rng.choice(ACTORS)}"
        elif form == 1:
            line = f"{rng.choice(THINGS)} {rng.choice(STATES)}"
        else:
            line = f"{rng.choice(ACTORS)} reports that {rng.choice(THINGS)} {rng.choice(STATES)}"
        lines.add(line[0].upper() + line[1:] if rng.random() < 0.7 else line)
    return sorted(lines)
