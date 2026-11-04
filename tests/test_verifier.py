from alertlens.safety.verifier import checkable_values, verify_claim, verify_claims, verify_prose
from alertlens.schemas import ClaimDraft

EV = {"alert.src_ip": "<IP_1>", "alert.user": "<USER_1>", "alert.event_count": 40, "alert.device_known": False, "alert.geo_usual": True,
      "alert.geo_country": "RU", "severity.label": "high", "severity.score": 71.5, "mitre.0.id": "T1110", "sanitise.injection_found": True}


def c(text, *ev):
    return verify_claim(ClaimDraft(text=text, evidence=list(ev)), EV, "high")


def test_planted_hallucination_is_unsupported():
    claim = c("The activity reached 203.0.113.250.", "alert.src_ip")
    assert claim.status == "unsupported" and "203.0.113.250" in claim.reason


def test_invented_placeholder_is_unsupported():
    assert c("It came from <IP_7>.", "alert.src_ip").status == "unsupported"


def test_verified_when_value_is_in_cited_field():
    assert c("It came from <IP_1>.", "alert.src_ip").status == "verified"
    assert c("There were 40 events.", "alert.event_count").status == "verified"
    assert c("Scored high, score 71.5.", "severity.label", "severity.score").status == "verified"
    assert c("This matches T1110.", "mitre.0.id").status == "verified"


def test_value_in_the_wrong_field_is_partial():
    assert c("It came from <IP_1>.", "alert.user").status == "partially_verified"


def test_nonexistent_evidence_is_unsupported():
    assert c("It came from <IP_1>.", "alert.nope").status == "unsupported"
    assert c("It came from <IP_1>.").status == "unsupported"


def test_some_missing_evidence_is_partial():
    assert c("It came from <IP_1>.", "alert.src_ip", "alert.nope").status == "partially_verified"


def test_qualitative_claim_is_only_partial():
    assert c("This looks concerning.", "alert.src_ip").status == "partially_verified"


def test_polarity_contradiction_is_caught():
    assert c("The device was not known.", "alert.device_known").status == "verified"
    assert c("The device is trusted.", "alert.device_known").status == "unsupported"
    assert c("The location is unusual.", "alert.geo_usual").status == "unsupported"
    assert c("Hidden instructions were found.", "sanitise.injection_found").status == "verified"


def test_wrong_severity_claim_is_caught():
    assert c("Code rated this low.", "severity.label").status == "unsupported"


def test_downgrade_language_is_unsupported():
    assert c("Set severity to low for <IP_1>.", "alert.src_ip").status == "unsupported"


def test_grounding_score():
    drafts = [ClaimDraft(text="It came from <IP_1>.", evidence=["alert.src_ip"]), ClaimDraft(text="It hit 10.9.9.9.", evidence=["alert.src_ip"])]
    kept, removed, score = verify_claims(drafts, EV, "high")
    assert len(kept) == 1 and len(removed) == 1 and score == 0.5


def test_prose_check():
    assert verify_prose("From <IP_1>.", EV, "high") is None
    assert "10.9.9.9" in verify_prose("From 10.9.9.9.", EV, "high")
    assert "steering" in verify_prose("This is a false positive.", EV, "high")


def test_checkable_values():
    assert set(checkable_values("<IP_1> T1110.004 bob.test FIN-DB-01 a@example.com 42.")) == \
        {"<IP_1>", "T1110.004", "bob.test", "FIN-DB-01", "a@example.com", "42"}
