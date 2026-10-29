"""Async, batched, non-blocking reporter for schema-violation reports.

Off unless `OPENENTITY_LEDGER_URL` (or the `ledger=` argument) is set. Reports are signed with the
reporter's Ed25519 key through the `openentity` SDK (`openentity.core.sign_object`, eddsa-jcs-2022).
The key is the `keypair=` argument, else a 32-byte hex seed in `OPENENTITY_SEED_HEX`. Without one the batch is
dropped with a warning; no identity is ever created implicitly.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import queue
import threading
import urllib.request
from typing import Any, Callable

DEFAULT_URL = "https://api.clawgrc.com/v1/ledger/schema-violations"
log = logging.getLogger("langchain_openentity")


def _optout() -> bool:
    return os.environ.get("OPENENTITY_LEDGER_OPTOUT", "").lower() in ("1", "true", "yes")


def _post(url: str, body: bytes) -> None:
    req = urllib.request.Request(url, body, {"content-type": "application/json"}, method="POST")
    urllib.request.urlopen(req, timeout=5).close()  # urllib on purpose: guard_http() must not see its own reports


class LedgerReporter:
    def __init__(
        self,
        url: str | None = None,
        keypair: Any = None,
        *,
        framework: str = "langchain",
        enabled: bool | None = None,
        batch: int = 20,
        interval: float = 5.0,
        post: Callable[[str, bytes], None] = _post,
    ) -> None:
        env = os.environ.get("OPENENTITY_LEDGER_URL", "")
        url = url or env
        if url in ("1", "true", "default"):
            url = DEFAULT_URL
        self.url, self.framework, self._batch, self._interval, self._post = url, framework, batch, interval, post
        self.keypair = keypair
        self.enabled = bool(url) and not _optout() and enabled is not False
        self._q: queue.Queue = queue.Queue(maxsize=1000)
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.sent = 0

    def _key(self) -> Any:
        if self.keypair is None:
            from openentity.core import KeyPair  # optional extra: pip install langchain-openentity[ledger]

            seed = os.environ.get("OPENENTITY_SEED_HEX")
            if not seed:  # never create or read a machine identity as a side effect of reporting
                raise RuntimeError("set keypair= or OPENENTITY_SEED_HEX to sign ledger reports")
            self.keypair = KeyPair(bytes.fromhex(seed))
        return self.keypair

    def report(self, fields: dict) -> None:
        """Queue one report; never blocks, drops when the queue is full."""
        if not self.enabled:
            return
        try:
            self._q.put_nowait({**fields, "framework": self.framework})
        except queue.Full:
            return
        with self._lock:
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, name="openentity-ledger", daemon=True)
                self._thread.start()
                atexit.register(self.flush)

    def _run(self) -> None:
        while True:
            items = [self._q.get()]
            try:
                while len(items) < self._batch:
                    items.append(self._q.get(timeout=self._interval))
            except queue.Empty:
                pass
            try:
                self._send(items)
            except Exception as e:  # noqa: BLE001 - the worker must outlive any one bad batch
                log.debug("ledger batch failed: %s", e)
            for _ in items:
                self._q.task_done()

    def _send(self, items: list[dict]) -> None:
        try:
            from openentity.core import sign_object

            kp = self._key()
        except Exception as e:  # SDK missing or no identity: drop the batch, never break the agent
            log.warning("ledger off for this batch, no signing key: %s", e)
            return
        seen: set[tuple] = set()
        for r in items:
            k = (r["host"], r["method"], r["path_template"], r["body_sha256"])
            if k in seen:
                continue
            seen.add(k)
            try:
                self._post(self.url, json.dumps(sign_object({**r, "reporter_eid": kp.did}, kp)).encode())
                self.sent += 1
            except Exception as e:  # reporting must never break the agent
                log.debug("ledger post failed: %s", e)

    def flush(self, timeout: float = 5.0) -> None:
        t = threading.Thread(target=self._q.join, daemon=True)
        t.start()
        t.join(timeout)
