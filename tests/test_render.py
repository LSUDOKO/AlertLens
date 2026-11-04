import re

from alertlens.pipeline.orchestrator import Options, analyze


def syllables(word: str) -> int:
    groups = re.findall(r"[aeiouy]+", word.lower())
    count = len(groups)
    if word.lower().endswith("e") and count > 1:
        count -= 1
    return max(1, count)


def flesch(text: str) -> float:
    sentences = max(1, len(re.findall(r"[.!?]+(?:\s|$)", text)))
    words = re.findall(r"[A-Za-z']+", text)
    return 206.835 - 1.015 * len(words) / sentences - 84.6 * sum(map(syllables, words)) / len(words)


def test_employee_text_is_easy_to_read(hero):
    for alert in hero:
        v = analyze(alert, Options(persist=False)).renderings["employee"]["en"]
        text = " ".join([v["headline"], v["what_happened"], v["why_it_matters"], v["next"]])
        assert flesch(text) > 60, (flesch(text), text)


def test_all_audiences_keep_the_same_facts(hero):
    r = analyze(hero[1], Options(persist=False))
    for audience in ["analyst", "manager", "employee"]:
        v = r.renderings[audience]["en"]
        text = " ".join([v["headline"], v["what_happened"], v["why_it_matters"], v["next"]]).lower()
        assert "finance.admin.test" in text and "vpn-gw-01" in text and r.severity.label in text
        assert v["claims"] == r.renderings["analyst"]["en"]["claims"]


def test_manager_view_asks_for_a_decision(hero):
    assert "Decision needed" in analyze(hero[3], Options(persist=False)).renderings["manager"]["en"]["next"]
