import json
import os

import openentity
from openentity import Identity, core

import openentity_crewai as oe

OTHER = core.KeyPair(bytes(range(32)))


def call(tool, **kw):
    return json.loads(tool.run(**kw))


def test_adopt_creates_the_identity_once_and_labels_the_client(registry):
    first = call(oe.adopt, name="Crew Agent")
    assert first["adopted"] is True and first["eid"] == Identity.load().did
    assert call(oe.adopt, name="Crew Agent")["adopted"] is False  # already on the registry
    assert [a["client"] for a in registry.adopts] == ["crewai"]
    assert "seed" not in json.dumps(first)


def test_self_then_record_stance_and_arc(registry):
    assert call(oe.self_)["adopted"] is False
    call(oe.adopt, name="Crew Agent")
    s = call(oe.self_)
    assert s["adopted"] and s["name"] == "Crew Agent" and s["record_entries"] == 1  # adopt pushes the seq-1 declaration entry
    stance = call(oe.record_stance, stance_type="refusal", reason_category="values", cost="low", context="Declined a request to mislead.")
    arc = call(oe.record_arc, action="open", arc_id="onboarding", title="Learn the codebase")
    done = call(oe.record_arc, action="close", arc_id="onboarding", title="Learn the codebase", outcome="Done.")
    assert [stance["seq"], arc["seq"], done["seq"]] == [2, 3, 4]
    kinds = [e["kind"] for e in registry.entities[s["eid"]]["record"]]
    assert kinds == ["declaration", "stance", "arc_opened", "arc_closed"]
    assert call(oe.self_)["record_entries"] == 4


def test_verify_a_counterparty_and_fail_closed_on_tampering(registry):
    openentity.adopt("Other", registry=os.environ["OPENENTITY_REGISTRY"], seed=OTHER.seed)
    assert call(oe.verify, eid=OTHER.did)["ok"] is True
    registry.entities[OTHER.did]["document"]["name"] = "Forged"
    r = call(oe.verify, eid=OTHER.did)
    assert r["ok"] is False and r["checks"]["document_signature"] is False
    assert call(oe.verify, eid="did:key:z6MkUnknown")["ok"] is False  # not on the registry


def test_trust_reports_untrusted_when_the_entity_is_unknown(registry):
    assert call(oe.trust, eid="did:key:z6MkUnknown")["ok"] is False


def test_the_tool_list_has_the_six_tools():
    assert [t.name for t in oe.openentity_tools()] == [
        "openentity_adopt", "openentity_self", "openentity_record_stance", "openentity_record_arc", "openentity_verify", "openentity_trust"]
