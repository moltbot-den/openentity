"""The agent side of the OpenEntity Account (docs/mobile/PLAN.md 8.1 to 8.4; contract: account/openapi.yaml, tag "Agent API").

pair() links an agent's did:key to its owner; Owner messages the owner, reports status, asks approvals and receives commands.
Every call is RFC 9421-signed by the agent's did:key. The standard library has no WebSocket client, so Owner.on_command polls
GET /v1/agent/messages every 15 seconds, the contract's fallback; the TypeScript SDK holds the WebSocket."""
import json
import re
import socket
import time
import urllib.error
import urllib.request
from threading import Event, Thread
from urllib.parse import quote, urlsplit

from . import core
from .client import _VERSION
from .errors import InvalidInputError, OpenEntityError, VerificationError
from .httpsig import sign_request
from .identity import Identity
from .pair import pair_sas

ACCOUNT = "https://account.openentity.org"
_CODE = re.compile(r"OE-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}")


def _keypair(identity) -> core.KeyPair:
    """An Identity or a KeyPair; None loads (or creates) this machine's Identity."""
    return getattr(identity or Identity.load_or_create(), "kp", identity)


def _call(kp: core.KeyPair, base: str, method: str, path: str, body=None):
    """One signed call. A refusal raises OpenEntityError with the service's `code`, `status` and, on 429, `retry_after`."""
    url, data = base + path, b"" if body is None else json.dumps(body).encode()
    headers = {"accept": "application/json", "user-agent": f"openentity-python/{_VERSION}", **sign_request(method, url, data, kp, kp.did)}
    if data:
        headers["content-type"] = "application/json"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data or None, method=method, headers=headers), timeout=30) as r:
            text = r.read()
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            err = json.loads(raw)
        except ValueError:
            err = None
        code = err["error"] if isinstance(err, dict) and isinstance(err.get("error"), str) else "account_error"
        out = OpenEntityError(f"account {e.code} for {method} {path}: {err.get('message', '') if isinstance(err, dict) else raw[:200]}", code)
        out.status, out.retry_after = e.code, int(e.headers.get("retry-after") or 0) or None
        raise out from None
    return json.loads(text) if text else None


def pair(code: str, identity=None, framework: str = "other", sdk: str = "openentity", sdk_version: str = _VERSION,
         host: str | None = None, account: str = ACCOUNT, on_match=None) -> dict:
    """Pair this agent with its owner (PLAN 8.1). `code` is the OE-XXXX-XXXX code the owner's app shows.

    Signs a Presentation (audience = the account service DID, nonce = "pair:" + the code) into POST /v1/pair, checks that the
    service's match items equal the ones computed here from this agent's own DID (else it refuses: a service must not be able to
    substitute another agent), hands them to `on_match` (default: prints "Match: ..."), then polls until the owner confirms,
    rejects or the code expires. Returns {"pairing_id", "owner_did", "permissions", "credentials", "match"}; bearer credentials appear only here.
    Raises OpenEntityError: pairing_rejected, pairing_expired, verification_failed (match mismatch) or the service's code."""
    kp, base = _keypair(identity), account.rstrip("/")
    c = str(code).strip().upper()
    if not _CODE.fullmatch(c):
        raise InvalidInputError("the pairing code looks like OE-XXXX-XXXX")
    match = pair_sas(c, kp.did)
    # "pair:" + the code: OEIS-1 nonces have at least 16 characters, so the bare code would fail verify_presentation.
    presentation = core.build_presentation(kp, "did:web:" + urlsplit(base).netloc.replace(":", "%3A"), f"pair:{c}")
    claim = _call(kp, base, "POST", "/v1/pair", {"code": c, "presentation": presentation, "framework": framework, "sdk": sdk,
                                                 "sdk_version": sdk_version, "host": host or socket.gethostname()})
    sas = (claim or {}).get("sas") or {}
    if sas.get("version") != "pair-sas/1" or sas.get("names") != match:
        raise VerificationError("the account service's match items differ from the ones this agent computes from its own DID; not pairing")
    (on_match or (lambda names: print("Match: " + ", ".join(names), flush=True)))(match)
    every = min(max(int(claim.get("poll_interval") or 2), 2), 60)  # the contract says 2; never faster
    until = (claim.get("expires_at") or time.time() + 600) + 30
    while True:
        time.sleep(every)
        try:
            s = _call(kp, base, "GET", f"/v1/pair/{quote(claim['pairing_id'], safe='')}")
        except (OpenEntityError, OSError) as e:  # a blip during a wait of minutes is not a failed pairing
            status = getattr(e, "status", None)
            if (status is None or status == 429 or status >= 500) and time.time() < until:
                time.sleep(getattr(e, "retry_after", None) or 0)
                continue
            raise
        if s["state"] == "confirmed":
            return {"pairing_id": claim["pairing_id"], "owner_did": s["owner_did"], "permissions": s.get("permissions") or [],
                    "credentials": s.get("credentials") or [], "match": match}
        if s["state"] in ("rejected", "expired"):
            raise OpenEntityError(f"the owner's app reports the pairing {s['state']}", f"pairing_{s['state']}")
        if time.time() > until:
            raise OpenEntityError("the pairing code expired before the owner confirmed", "pairing_expired")


class Owner:
    """The paired agent's channel to its owner. Construct it from the same key that paired; every call is RFC 9421-signed."""

    def __init__(self, identity=None, account: str = ACCOUNT):
        self._kp = _keypair(identity)
        self.did, self.account = self._kp.did, account.rstrip("/")

    def _call(self, method: str, path: str, body=None):
        return _call(self._kp, self.account, method, path, body)

    def message(self, text: str, attachments: list[str] | None = None) -> dict:
        """Message the owner (at most 4096 UTF-8 bytes; 60 an hour). `attachments` are upload ids from POST /v1/agent/uploads."""
        return self._call("POST", "/v1/agent/messages", {"text": text, **({"attachments": attachments} if attachments else {})})

    def status(self, state: str, summary: str, progress: float | None = None) -> None:
        """state: running|idle|blocked|error|done; the owner's app shows it (Live Activity). `progress` is 0 to 1."""
        self._call("POST", "/v1/agent/status", {"state": state, "summary": summary, **({"progress": progress} if progress is not None else {})})

    def ask_approval(self, title: str, summary: str, risk: str, expires_in: int = 600, details: dict | None = None,
                     wait: bool = False) -> dict:
        """Ask the owner to approve something (risk: low|medium|high; expires_in 60 to 600 seconds). The app labels it "Written by
        the agent" and no product accepts it as an approval of its own. With `wait`, polls every 5 seconds until decided or expired."""
        r = self._call("POST", "/v1/agent/approvals", {"title": title, "summary": summary, "risk": risk, "expires_in": expires_in,
                                                       **({"details": details} if details else {})})
        while wait and r["state"] == "pending" and time.time() < r["expires_at"] + 10:
            time.sleep(5)
            r = self._call("GET", f"/v1/agent/approvals/{quote(r['id'], safe='')}")
        return r

    def inbox(self, ack: bool = True) -> dict:
        """Unacknowledged items, oldest first (up to 100), acknowledged on return unless ack=False. At most once every 15 seconds."""
        r = self._call("GET", "/v1/agent/messages")
        if ack and r["items"]:
            self._call("POST", "/v1/agent/messages/ack", {"ids": [i["id"] for i in r["items"]]})
        return r

    def renew_credentials(self, products: list[str] | None = None) -> list[dict]:
        """New product keys (PLAN 8.4); the old ones stay valid for 1 hour. Default: every product the agent holds a key for."""
        return self._call("POST", "/v1/agent/credentials/renew", {"products": products} if products else {})["credentials"]

    def on_command(self, handler, on_error=None, interval: int = 15) -> "Listener":
        """Every item of the owner's channel (commands, messages, approval results, permissions) goes to `handler(item)` on a
        background thread, one at a time, and is acknowledged once it returns; a handler that raises leaves it for the next poll.
        Polls GET /v1/agent/messages every `interval` seconds (15 at least: faster calls get 429). Stops on not_paired."""
        return Listener(self, handler, on_error, max(interval, 15))


class Listener:
    """The polling loop behind Owner.on_command. `paused` follows pause and resume commands; close() stops it."""

    def __init__(self, owner: Owner, handler, on_error, interval: int):
        self._owner, self._handler, self._report, self._interval = owner, handler, on_error or (lambda e: None), interval
        self._halt, self._seen, self.paused = Event(), set(), False
        self._thread = Thread(target=self._run, daemon=True, name="openentity-owner-channel")
        self._thread.start()

    @property
    def mode(self) -> str:
        return "closed" if self._halt.is_set() else "poll"

    def close(self):
        self._halt.set()

    def _handle(self, item: dict) -> bool:
        if item["id"] in self._seen:
            return True
        if item.get("type") == "command" and item.get("command") in ("pause", "resume"):
            self.paused = item["command"] == "pause"
        try:
            self._handler(item)
        except Exception as e:  # the item stays unacknowledged and comes back
            self._report(e)
            return False
        self._seen.add(item["id"])
        return True

    def _run(self):
        refused = False
        while not self._halt.is_set():
            wait = self._interval
            try:
                r = self._owner._call("GET", "/v1/agent/messages")
                if refused:  # answered after agent_paused: resumed
                    self.paused = refused = False
                done = [i["id"] for i in r["items"] if not self._halt.is_set() and self._handle(i)]
                if done:
                    self._owner._call("POST", "/v1/agent/messages/ack", {"ids": done})
            except Exception as e:
                if getattr(e, "status", None) == 403:  # not_paired: nothing will arrive
                    self._halt.set()
                if getattr(e, "code", None) == "agent_paused":
                    self.paused = refused = True
                wait = getattr(e, "retry_after", None) or wait
                self._report(e)
            self._halt.wait(wait)
