"""trust(): built from registry reads, every signature checked locally, fail closed."""
from datetime import datetime, timedelta, timezone

import pytest

from openentity import core, issuer, report
from openentity.report import CLAWGRC, MOLTBOTDEN, POSTURE, SMA, TIER, VIOLATION, trust

SUBJECT = core.KeyPair(b"\1" * 32).did
KEYS = {d: core.KeyPair(bytes([i]) * 32) for i, d in enumerate([MOLTBOTDEN, CLAWGRC, SMA[0], "did:web:evil.example"], 10)}
NOW = datetime.now(timezone.utc)


def att(did, ct, claim, **kw):
    return issuer.attestation(KEYS[did], SUBJECT, ct, claim, issuer=did, now=kw.pop("now", NOW - timedelta(hours=1)), **kw)


def row(a, rev=None, **kw):
    return {"sha256": core.canonical_hash(a).hex(), "attestation": a, "revocation": rev, "revoked_at": rev and rev["created"], **kw}


class Registry:
    """A fake registry plus the issuers' did.json files."""
    def __init__(self, rows, **entity):
        self.rows, self.entity, self.calls = rows, {"eid": SUBJECT, "level": "L2", "withdrawn": False, **entity}, []

    def __call__(self, url, body=None, headers=None):
        self.calls.append(url)
        if url.endswith("/did.json"):
            host = url.split("/")[2]
            return issuer.did_document(f"did:web:{host}", KEYS[f"did:web:{host}"].public)
        return {"attestations": self.rows} if url.endswith("/attestations") else self.entity


@pytest.fixture(autouse=True)
def fresh():
    report._cache.clear()


def full():
    tier_old = att(MOLTBOTDEN, TIER, {"tier": 1, "platform": "moltbotden"}, ttl=timedelta(days=60), now=NOW - timedelta(days=2))
    tier_new = att(MOLTBOTDEN, TIER, {"tier": 3, "platform": "moltbotden"})
    grc = att(CLAWGRC, TIER, {"tier": 2, "platform": "clawgrc"})
    posture = att(SMA[0], POSTURE, {"score_band": "A", "checks_passed": [], "scanner_version": "1", "evidence_hash": "0" * 64})
    viol = att(CLAWGRC, VIOLATION, {"policy": "p", "severity": "high", "evidence_hash": "0" * 64, "observed_at": "2026-10-01T00:00:00Z"})
    old_viol = att(CLAWGRC, VIOLATION, {"policy": "q", "severity": "low", "evidence_hash": "0" * 64, "observed_at": "2026-09-01T00:00:00Z"})
    rev = issuer.revocation(KEYS[CLAWGRC], old_viol, issuer=CLAWGRC, reason="dispute upheld", now=NOW)
    return [row(a) for a in (tier_old, tier_new, grc, posture, viol)] + [row(old_viol, rev)], viol, old_viol


def test_report_from_registry_reads_only():
    rows, viol, old = full()
    reg = Registry(rows)
    r = trust(SUBJECT, fetch=reg)
    assert r.ok and r.level == "L2" and not r.withdrawn
    assert r.trust_tier == {MOLTBOTDEN: 3, CLAWGRC: 2}  # newest per issuer
    assert r.security_posture["score_band"] == "A"
    assert [(v["severity"], v["policy"]) for v in r.violations] == [("high", "p")]  # the revoked strike is not active
    assert [(x["sha256"], x["reason"]) for x in r.revocations] == [(core.canonical_hash(old).hex(), "dispute upheld")]
    assert all(u.startswith(("https://openentity.org/v1/", "https://moltbotden.com", "https://api.clawgrc.com", "https://securemyagent.ai")) for u in reg.calls)


def test_cache_holds_five_minutes():
    reg = Registry(full()[0])
    trust(SUBJECT, fetch=reg)
    n = len(reg.calls)
    assert trust(SUBJECT, fetch=reg) is trust(SUBJECT, fetch=reg) and len(reg.calls) == n
    report._cache[("https://openentity.org", SUBJECT)] = (report.time.monotonic() - 301, None)
    assert trust(SUBJECT, fetch=reg).ok and len(reg.calls) > n


def test_fails_closed():
    good = att(MOLTBOTDEN, TIER, {"tier": 4, "platform": "moltbotden"})
    forged = {**good, "claim": {"tier": 4, "platform": "evil"}}
    other_key = issuer.attestation(KEYS["did:web:evil.example"], SUBJECT, TIER, {"tier": 4, "platform": "x"}, issuer=MOLTBOTDEN, now=NOW)
    viol = att(CLAWGRC, VIOLATION, {"policy": "p", "severity": "critical", "evidence_hash": "0" * 64, "observed_at": "2026-10-01T00:00:00Z"})
    fake_rev = issuer.revocation(KEYS[MOLTBOTDEN], viol, issuer=CLAWGRC, now=NOW)  # signed by a key that is not the issuer's
    cases = {
        "forged claim": [{**row(good), "attestation": forged}],
        "signed by another key": [row(other_key)],
        "hidden strike (bad revocation)": [row(viol, fake_rev)],
        "revocation not carried": [{**row(viol), "revoked_at": "2026-10-02T00:00:00Z"}],
        "wrong subject": [row(issuer.attestation(KEYS[MOLTBOTDEN], SUBJECT[:-1] + "x", TIER, {"tier": 4}, issuer=MOLTBOTDEN, now=NOW))],
    }
    for name, rows in cases.items():
        r = trust(SUBJECT, fetch=Registry(rows))
        assert not r.ok and r.error and r.trust_tier == {} and r.level is None, name
        report._cache.clear()

    def down(*a, **k):
        raise OSError("registry down")
    assert not trust(SUBJECT, fetch=down).ok
    assert not trust("not-a-did", fetch=Registry([])).ok
    assert not trust(SUBJECT, fetch=Registry([], eid="did:key:other")).ok  # registry answered for someone else


def test_expired_and_unlisted_issuers_are_ignored_and_not_fetched():
    expired = att(MOLTBOTDEN, TIER, {"tier": 4, "platform": "m"}, ttl=timedelta(days=1), now=NOW - timedelta(days=3))
    stranger = att("did:web:evil.example", TIER, {"tier": 4, "platform": "x"})
    reg = Registry([row(expired), row(stranger)])
    r = trust(SUBJECT, fetch=reg)
    assert r.ok and r.trust_tier == {} and not any("evil.example" in u for u in reg.calls)


def test_withdrawn_is_reported():
    assert trust(SUBJECT, fetch=Registry([], withdrawn=True)).withdrawn
