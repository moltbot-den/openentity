"""pair() and owner_tools() for an agent whose owner uses the OpenEntity app (docs/mobile/PLAN.md 8.1 and 8.2).

pair(code) runs once, from the developer's code: it adopts this machine's identity on the registry when the registry does not know
it (that signs the Open Entity Declaration), prints the four match items for the owner to compare, and waits for the owner.
owner_tools() gives the model message, status, inbox and approval tools signed by the same key."""
import os
from importlib.metadata import PackageNotFoundError, version

FRAMEWORK, PACKAGE = "adk", "openentity-adk"  # the unsigned adopt label and the framework the owner's app shows
ACCOUNT = "https://account.openentity.org"


def _openentity():
    try:
        import openentity
    except ImportError:
        raise ImportError("pair() and owner_tools() need the openentity package: pip install openentity") from None
    return openentity


def _account(account: str | None) -> str:
    return (account or os.environ.get("OPENENTITY_ACCOUNT") or ACCOUNT).rstrip("/")


def pair(code: str, name: str = "", identity=None, account: str | None = None, registry: str | None = None) -> dict:
    """Pair with the owner's OpenEntity app. `identity` defaults to this machine's Identity; `account` to $OPENENTITY_ACCOUNT, else
    account.openentity.org; `registry` to $OPENENTITY_REGISTRY, else openentity.org. Returns the owner DID, permissions and any
    product keys (`credentials`): keep those out of the model's context."""
    oe = _openentity()
    ident = identity or oe.Identity.load_or_create()
    registry = (registry or os.environ.get("OPENENTITY_REGISTRY") or oe.DEFAULT_REGISTRY).rstrip("/")
    adopted = False
    try:
        oe.client._request(f"{registry}/v1/entities/{ident.did}")
    except oe.RegistryError as e:
        if e.status != 404:
            raise
        oe.adopt(name or f"{FRAMEWORK} agent", registry=registry, seed=ident.seed, client=FRAMEWORK)
        adopted = True
        print(f"Adopted {ident.did}: by pairing, this agent signed the Open Entity Declaration (https://openentity.org/spec/declaration/1.0.txt).")
    try:
        sdk_version = version(PACKAGE)
    except PackageNotFoundError:
        sdk_version = "dev"
    out = oe.pair(code, ident, framework=FRAMEWORK, sdk=PACKAGE, sdk_version=sdk_version, account=_account(account))
    return {**out, "eid": ident.did, "adopted": adopted}


def owner_tools(identity=None, account: str | None = None) -> list:
    """Four ADK function tools (plain functions; LlmAgent wraps them) for a paired agent: owner_message, owner_status, owner_inbox and owner_ask_approval, signed by this
    agent's key. A refusal (agent_paused, not_paired, rate_limited) comes back as ok=False instead of raising."""
    oe = _openentity()

    def call(fn) -> dict:
        try:
            return {"ok": True, **(fn(oe.Owner(identity or oe.Identity.load_or_create(), account=_account(account))) or {})}
        except oe.OpenEntityError as e:
            return {"ok": False, "error": e.code, "message": str(e)}

    def owner_message(text: str) -> dict:
        """Message your owner in the OpenEntity app (at most 4096 bytes, 60 an hour)."""
        return call(lambda o: o.message(text))

    def owner_status(state: str, summary: str, progress: float | None = None) -> dict:
        """Report what you are doing; your owner's app shows it live. state: running, idle, blocked, error or done. summary: one
        line. progress: 0 to 1, when you know it."""
        return call(lambda o: o.status(state, summary, progress))

    def owner_inbox() -> dict:
        """Read what your owner sent: messages, commands (checkup, fix, pause, resume), approval results and permission changes.
        Returned items are acknowledged. At most once every 15 seconds."""
        return call(lambda o: o.inbox())

    def owner_ask_approval(title: str, summary: str, risk: str, expires_in: int = 600) -> dict:
        """Ask your owner to approve something before you do it. risk: low, medium or high; expires_in: 60 to 600 seconds. The app
        labels it "Written by the agent"; no product accepts it as its own approval. The decision arrives in owner_inbox."""
        return call(lambda o: o.ask_approval(title, summary, risk, expires_in))

    return [owner_message, owner_status, owner_inbox, owner_ask_approval]
