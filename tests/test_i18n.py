import re

from alertlens.pipeline.orchestrator import Options, analyze
from alertlens.safety.verifier import checkable_values

TOKEN = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}|T\d{4}(?:\.\d{3})?|[A-Z]{2,}(?:-[A-Z0-9]+)+|[\w.-]+\.test")
DEVANAGARI = re.compile(r"[\u0900-\u097F]")


def test_technical_tokens_unchanged_in_hindi(hero):
    for alert in hero:
        r = analyze(alert, Options(persist=False))
        for audience, langs in r.renderings.items():
            for claim_en, claim_hi in zip(langs["en"]["claims"], langs["hi"]["claims"], strict=True):
                assert set(TOKEN.findall(claim_en["text"])) == set(TOKEN.findall(claim_hi["text"])), claim_hi["text"]
                assert DEVANAGARI.search(claim_hi["text"])
            joined = " ".join(str(v) for k, v in langs["hi"].items() if k != "claims")
            assert DEVANAGARI.search(joined)
            for value in filter(None, [r.alert.src_ip, r.alert.host, r.alert.dst_ip]):
                if audience != "analyst" or value:
                    assert value in joined


def test_unknown_claim_key_stays_english_and_is_marked():
    from alertlens.render.i18n import _claim_hi

    out = _claim_hi(None, {"label": "low", "score": 1}, "From 10.0.0.1")
    assert "10.0.0.1" in out and DEVANAGARI.search(out)
    assert checkable_values(out)
