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


def test_guessed_attack_stage_is_removed_unless_evidence_backs_it():
    from alertlens.safety.verifier import unsupported_concept, verify_claim
    from alertlens.schemas import ClaimDraft

    plain = {"alert.user": "<USER_1>", "mitre.0.tactic": "Command and Control"}
    guess = ClaimDraft(text="<USER_1> shows potential lateral movement.", evidence=["alert.user"])
    assert verify_claim(guess, plain, "high").status == "unsupported"
    backed = {**plain, "mitre.1.tactic": "Lateral Movement"}
    assert verify_claim(guess, backed, "high").status != "unsupported"
    assert unsupported_concept("This fits the Command and Control stage.", plain) is None


def test_admin_claim_needs_admin_evidence():
    from alertlens.safety.verifier import unsupported_concept

    assert unsupported_concept("It was performed by an admin user.", {"facts.is_admin_action": False}) == "an admin action"
    assert unsupported_concept("It was performed by an admin user.", {"facts.is_admin_action": True}) is None
    assert unsupported_concept("It was performed by an admin user.", {"alert.privilege": "admin"}) is None


def test_vague_summary_is_caught():
    from alertlens.safety.verifier import vague_summary

    assert vague_summary("Security Alert", "high")
    assert not vague_summary("High severity: a login", "high")


def test_number_copied_from_elsewhere_is_removed():
    from alertlens.safety.verifier import verify_claim
    from alertlens.schemas import ClaimDraft

    evidence = {"alert.rule_level": 8, "severity.score": 92.3}
    wrong = ClaimDraft(text="The rule fired at level 9.", evidence=["alert.rule_level"])
    right = ClaimDraft(text="The rule fired at level 8.", evidence=["alert.rule_level"])
    assert verify_claim(wrong, evidence, "high").status == "unsupported"
    assert verify_claim(right, evidence, "high").status == "verified"


def test_denying_admin_is_not_a_guess():
    from alertlens.safety.verifier import unsupported_concept

    assert unsupported_concept("<USER_1> is not an admin.", {"facts.is_admin_action": False}) is None


def test_real_model_schema_caps_claims_but_templates_can_list_more():
    from alertlens.schemas import ClaimDraft, ExplanationDraft

    assert ExplanationDraft.model_json_schema()["properties"]["claims"]["maxItems"] == 6
    many = [ClaimDraft(text="x", evidence=["alert.user"]) for _ in range(9)]
    assert len(ExplanationDraft(summary="s", what_happened="w", why_it_matters="y", claims=many).claims) == 9
