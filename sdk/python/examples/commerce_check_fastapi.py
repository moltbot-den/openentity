"""FastAPI (or any Starlette app): one middleware in front of POST /buy.

allow runs the handler; step_up answers 428 with the cart the owner must approve; deny answers 403. Every answer carries `evidence_id`.
Run: uvicorn commerce_check_fastapi:app
"""
from fastapi import FastAPI, Request

from openentity.commerce import CommerceCheckMiddleware

MERCHANT = "did:web:shop.example"
POLICY = {"require_mandate": True, "require_owner": True}  # or {"merchant": MERCHANT} to use the policy you published


def cart_for(req: dict, agent_did: str | None) -> dict:
    """The cart/1 for POST /buy?total=<minor units> and the mandate the agent sent in OE-Mandate."""
    import base64
    import json
    from urllib.parse import parse_qs, urlparse

    total = int(parse_qs(urlparse(req["url"]).query).get("total", ["1000"])[0])
    try:
        mandate_id = json.loads(base64.urlsafe_b64decode(req["headers"]["oe-mandate"] + "==="))["mandate_id"]
    except Exception:
        mandate_id = None
    return {"profile": "cart/1", "merchant": MERCHANT, "agent_did": agent_did or "did:key:unknown",
            "lines": [{"sku": "dataset-1", "title": "Dataset", "qty": 1, "unit": total}], "total": total, "currency": "USD", "rail": "credits", "mandate_id": mandate_id}


def make_app(cart=cart_for, policy=POLICY, **options) -> FastAPI:
    app = FastAPI()
    app.add_middleware(CommerceCheckMiddleware, paths=["/buy"], cart=cart, policy=policy, **options)

    @app.post("/buy")
    def buy(request: Request):
        check = getattr(request.state, "agent_check", None) or {}  # empty only in observe mode when the check could not run
        return {"bought": True, "agent": check.get("agent_did"), "evidence_id": check.get("evidence_id")}

    return app


app = make_app()
