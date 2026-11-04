"""F22: Hindi from a template dictionary, so technical tokens pass through untouched.

Add a language by adding a dictionary shaped like HI. Claims a real LLM wrote have no template key,
so they stay in English and are marked.
"""
from __future__ import annotations

from alertlens.schemas import Explanation

LABEL = {"low": "कम", "medium": "मध्यम", "high": "गंभीर", "critical": "अत्यंत गंभीर"}


def _claim_hi(key: str | None, c: dict, en: str) -> str:
    """Hindi for a template claim, keyed by the same ids the English templates use."""
    user, host, src, dst = c.get("user"), c.get("host"), c.get("src_ip"), c.get("dst_ip")
    tech = c.get("techniques", [])
    names = c.get("technique_names", [])
    table = {
        "rule": f"नियम {c.get('rule_id')} स्तर {c.get('rule_level')} पर सक्रिय हुआ।",
        "events": f"सेंसर ने {c.get('event_count')} घटनाएँ दर्ज कीं।",
        "user": f"संबंधित खाता {user} है।",
        "src": f"यह गतिविधि {src} से आई।",
        "host": f"प्रभावित होस्ट {host} है, जिसकी महत्ता {c.get('criticality')} है।",
        "dst": f"गंतव्य पता {dst} था।",
        "volume": f"लगभग {c.get('volume_mb')} MB डेटा होस्ट से बाहर गया।",
        "device": "यह उपकरण इस खाते के लिए अनजान था।",
        "geo": f"स्थान {c.get('geo_country') or ''} इस खाते के लिए असामान्य है।",
        "tool": f"देखा गया टूल प्रकार {c.get('tool')} था।",
        "technique0": f"यह MITRE ATT&CK {tech[0]} ({names[0]}) से मेल खाता है।" if tech else en,
        "technique1": f"यह MITRE ATT&CK {tech[1]} ({names[1]}) से मेल खाता है।" if len(tech) > 1 else en,
        "severity": f"कोड आधारित स्कोरिंग ने इसे {LABEL[c['label']]} ({c['label']}) माना, स्कोर {c['score']}।",
        "injection": "इस अलर्ट में छिपे निर्देश मिले, जिनका पालन नहीं किया गया।",
    }
    return table.get(key, f"{en} (अंग्रेज़ी में)")


def _entities(c: dict) -> str:
    parts = []
    if c.get("user"):
        parts.append(f"खाता: {c['user']}।")
    if c.get("host"):
        parts.append(f"कंप्यूटर: {c['host']}।")
    if c.get("src_ip"):
        parts.append(f"स्रोत: {c['src_ip']}।")
    if c.get("dst_ip"):
        parts.append(f"गंतव्य: {c['dst_ip']}।")
    return " ".join(parts)


def hindi_rendering(audience: str, e: Explanation, c: dict) -> dict:
    label = f"{LABEL[c['label']]} ({c['label']})"
    tech = ", ".join(c.get("techniques", [])) or "कोई नहीं"
    stage = ", ".join(c.get("tactics", [])) or "कोई ज्ञात चरण नहीं"
    title = c.get("rule_id")
    claims = [{**cl.model_dump(), "text": _claim_hi(cl.key, c, cl.text)} for cl in e.claims]
    if audience == "analyst":
        head = f"गंभीरता {label}: नियम {title}। {_entities(c)}"
        what = f"सेंसर ने नियम {title} के तहत गतिविधि दर्ज की। {_entities(c)}"
        why = f"हमले का चरण: {stage}। कोड आधारित स्कोरिंग ने इसे {label} माना।"
        nxt = f"ATT&CK: {tech}। स्कोर {c['score']}, ट्राइएज {c['triage']}।"
    elif audience == "manager":
        first = c["actions"][0] if c["actions"] else "अभी कोई कार्रवाई नहीं"
        head = f"जोखिम: {label}। नियम {title}।"
        what = f"सेंसर ने नियम {title} के तहत गतिविधि दर्ज की। {_entities(c)}"
        why = f"हमले का चरण: {stage}। संपत्ति की महत्ता: {c.get('criticality')}। यदि यह वास्तविक है, तो व्यापारिक डेटा और सेवाओं पर असर पड़ सकता है।"
        nxt = f"निर्णय आवश्यक: \"{first}\" को स्वीकृत या अस्वीकार करें। बिना स्वीकृति कुछ भी नहीं चलता।"
    else:
        head = f"हमें कुछ असामान्य दिखा। इसका स्तर {label} है।"
        what = f"हमारे टूल ने असामान्य गतिविधि देखी। {_entities(c)}"
        why = "हो सकता है यह कुछ न हो, पर संभव है कि कोई और आपका खाता इस्तेमाल कर रहा हो। हम इसकी जाँच कर रहे हैं।"
        nxt = "घबराएँ नहीं। अपना पासवर्ड किसी को न बताएँ। यदि यह आपने नहीं किया, तो IT हेल्प डेस्क को फ़ोन करें।"
    return {"headline": head, "what_happened": what, "why_it_matters": why, "next": nxt, "claims": claims}
