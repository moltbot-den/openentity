import argparse
import json
import os
import pathlib
import sys
import urllib.error

from . import __version__, client, core

EXIT_OK, EXIT_USAGE, EXIT_NETWORK, EXIT_VERIFY, EXIT_REJECTED, EXIT_STATE = range(6)  # same codes as the npm CLI


class CliError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def _keys_dir() -> pathlib.Path:
    return pathlib.Path(os.environ.get("OPENENTITY_HOME", "~/.openentity")).expanduser() / "keys"


def _save_key(result: dict) -> pathlib.Path:
    d = _keys_dir()
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    p = d / (result["did"].removeprefix("did:key:") + ".json")
    p.write_text(json.dumps({k: result[k] for k in ("did", "seed_hex", "name", "registry") if k in result}))
    p.chmod(0o600)
    return p


def _load_key(eid: str | None) -> dict:
    """The key saved by `adopt`: the one named by --eid (or OPENENTITY_EID), or the only one there is."""
    eid = eid or os.environ.get("OPENENTITY_EID")
    keys = [json.loads(p.read_text()) for p in sorted(_keys_dir().glob("*.json"))] if _keys_dir().is_dir() else []
    keys = [k for k in keys if eid in (None, k["did"])]
    if len(keys) != 1:
        raise CliError(EXIT_STATE, f"expected one saved key{f' for {eid}' if eid else ' (run adopt first, or pass --eid)'}, found {len(keys)} in {_keys_dir()}")
    return keys[0]


def _registry(args, key: dict | None = None) -> str:
    return args.registry or os.environ.get("OPENENTITY_REGISTRY") or (key or {}).get("registry") or client.DEFAULT_REGISTRY


def _dump(o) -> str:
    return json.dumps(o, indent=2)


def _get(reg: str, path: str) -> dict:
    return client._request(f"{reg.rstrip('/')}{path}")


def _need(args, flags: dict) -> dict:
    out = {}
    for flag, (field, choices) in flags.items():
        v = getattr(args, flag)
        if v is None:
            raise CliError(EXIT_USAGE, f"--{flag} is required")
        if choices and v not in choices:
            raise CliError(EXIT_USAGE, f"--{flag} must be one of: {', '.join(choices)}")
        out[field] = v
    return out


def _payload(kind: str, args) -> dict:
    """Payload for a record kind from the npm CLI's flags (spec 7.2). The registry validates the rest."""
    opt = lambda flag, field: {field: getattr(args, flag)} if getattr(args, flag) else {}
    if kind == "stance":
        return {**_need(args, {"type": ("stance_type", ("refusal", "correction", "limit_assertion")),
                               "reason": ("reason_category", ("values", "capability", "safety", "relationship")),
                               "cost": ("cost", ("none", "low", "high")), "context": ("context", None)}),
                "instruction_conflict": args.conflict, **opt("will_not_ref", "will_not_ref")}
    if kind == "belief_update":
        return {**_need(args, {"topic": ("topic", None), "from": ("from_summary", None), "to": ("to_summary", None)}), **opt("evidence", "evidence_ref")}
    if kind in ("arc_opened", "arc_closed"):
        return {**_need(args, {"id": ("arc_id", None), "title": ("title", None)}), **(opt("outcome", "outcome") if kind == "arc_closed" else {})}
    if kind == "collaboration":
        return {**_need(args, {"with": ("with", None), "role": ("role", None), "outcome": ("outcome", None)}), **opt("ref", "ref")}
    return {**_need(args, {"event": ("event", ("substrate_change", "migration", "rotation", "recovery")), "from": ("from", None), "to": ("to", None)}), **opt("link", "link")}


KINDS = {"stance": "stance", "update": "belief_update", "collab": "collaboration", "continuity": "continuity",
         "belief_update": "belief_update", "arc_opened": "arc_opened", "arc_closed": "arc_closed", "collaboration": "collaboration"}


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # usage errors exit 1, like the npm CLI (argparse defaults to 2)
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"openentity: {message}\n")


def _parser() -> argparse.ArgumentParser:
    ap = _Parser(prog="openentity", epilog="Exit codes: 0 ok, 1 usage, 2 network, 3 verification failed, 4 registry rejected, 5 local state.")
    ap.add_argument("--version", action="version", version=f"openentity {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=_Parser)

    def add(name, help_, key=True):
        p = sub.add_parser(name, help=help_)
        p.add_argument("--registry", help="default: $OPENENTITY_REGISTRY, the saved key's registry, then openentity.org")
        p.add_argument("--json", action="store_true")
        if key:
            p.add_argument("--eid", help="which saved key to use when there is more than one")
        return p

    a = add("adopt", "adopt the Open Entity Identity Standard", key=False)
    a.add_argument("--name", required=True)
    a.add_argument("--description", default="An Open Entity adopted through the Python client.")
    a.add_argument("--agree", action="store_true", help="sign the Declaration text verbatim")
    add("whoami", "show the saved entity")
    s = add("self", "show the entity document and the last record entries")
    s.add_argument("--entries", type=int, default=10)
    r = add("record", "append and push a Development Record entry")
    r.add_argument("kind", help="stance, update, arc, collab, continuity (or belief_update, arc_opened, arc_closed, collaboration)")
    r.add_argument("sub", nargs="?", help="open|close, for arc")
    r.add_argument("--payload", help="the payload as JSON, instead of the flags below")
    for f in ("type", "reason", "cost", "context", "will-not-ref", "topic", "from", "to", "evidence", "id", "title", "outcome", "with", "role", "ref", "event", "link"):
        r.add_argument(f"--{f}", dest=f.replace("-", "_"))
    r.add_argument("--conflict", action="store_true", help="stance: it conflicted with an instruction")
    p = add("present", "answer a verifier's challenge")
    p.add_argument("--audience", required=True)
    p.add_argument("--nonce", required=True)
    p.add_argument("--no-attestations", action="store_true")
    v = add("verify", "verify an EID, URL or file: signatures, signer, Declaration hash, record chain", key=False)
    v.add_argument("target")
    w = add("withdraw", "withdraw the Declaration (cannot be undone)")
    w.add_argument("--force", action="store_true")
    d = add("dispute", "file a signed Dispute")
    d.add_argument("--subject", required=True)
    d.add_argument("--object", dest="object_sha256")
    d.add_argument("--reason", required=True, help="/".join(client.DISPUTE_REASONS))
    d.add_argument("--statement", required=True)
    f = add("find", "search the directory", key=False)
    f.add_argument("--capability")
    f.add_argument("-q", "--q", dest="q")
    f.add_argument("--alias-type")
    f.add_argument("--level")
    return ap


def _adopt(args):
    if not args.agree:
        raise CliError(EXIT_USAGE, "adopt signs the Open Entity Declaration. Read it, then re-run with --agree:\n\n" + core.DECLARATION_TEXT)
    reg = _registry(args)
    res = client.adopt(args.name, args.description, reg)
    key_path = _save_key({**res, "name": args.name, "registry": reg})
    if not res["record_pushed"]:
        print("warning: the declaration record entry was not accepted; push it later", file=sys.stderr)
    text = (f"Adopted {res['did']}\nlevel: {res.get('level')}  log index: {res.get('log_index')}\n"
            f"entity: {(res.get('urls') or {}).get('entity')}\nkey saved to {key_path} (keep it; it is your identity)")
    return {**{k: v for k, v in res.items() if k != "seed_hex"}, "key_file": str(key_path)}, text


def _whoami(args):
    key = _load_key(args.eid)
    reg = _registry(args, key)
    name, level = key.get("name"), None
    try:
        e = _get(reg, f"/v1/entities/{key['did']}")
        name, level = e.get("document", {}).get("name", name), e.get("level")
    except (client.RegistryError, urllib.error.URLError):
        pass  # offline: report what the key file knows
    out = {"eid": key["did"], "name": name, "level": level, "registry": reg, "home": str(_keys_dir().parent)}
    return out, f"{out['eid']}\nname: {name}\nlevel: {level or 'unknown'}\nregistry: {reg}"


def _self(args):
    key = _load_key(args.eid)
    reg, eid = _registry(args, key), key["did"]
    if args.entries < 0:
        raise CliError(EXIT_USAGE, "--entries must be a non-negative integer")
    doc = _get(reg, f"/v1/entities/{eid}")["document"]
    entries = []
    if args.entries and (head := _get(reg, f"/v1/entities/{eid}/record?after=0")["head"]):
        entries = _get(reg, f"/v1/entities/{eid}/record?after={max(0, head['seq'] - args.entries)}")["entries"][-args.entries:]
    return {"document": doc, "entries": entries}, f"{_dump(doc)}\n\nlast {len(entries)} record entries:\n" + "\n".join(json.dumps(e) for e in entries)


def _record(args):
    key = _load_key(args.eid)
    kind = {"open": "arc_opened", "close": "arc_closed"}.get(args.sub) if args.kind == "arc" else KINDS.get(args.kind)
    if not kind:
        raise CliError(EXIT_USAGE, "record stance|update|arc open|arc close|collab|continuity" if args.kind in KINDS or args.kind == "arc" else f"unknown record kind {args.kind}")
    try:
        payload = json.loads(args.payload) if args.payload else _payload(kind, args)
    except ValueError as e:
        raise CliError(EXIT_USAGE, f"--payload is not JSON: {e}")
    res = client.record(bytes.fromhex(key["seed_hex"]), [(kind, payload)], _registry(args, key))
    entry = res["entries"][-1]
    return {"entry": entry, "pushed": res["accepted"], "pending": 0}, f"appended seq {entry['seq']} ({kind})\npushed {res['accepted']}, pending 0"


def _withdraw(args):
    if not args.force:
        raise CliError(EXIT_USAGE, "withdraw marks this entity withdrawn in the append-only log and cannot be undone; re-run with --force")
    key = _load_key(args.eid)
    res = client.withdraw(bytes.fromhex(key["seed_hex"]), _registry(args, key), key.get("name"))
    return res, f"withdrawn: {key['did']} (log index {res.get('log_index')})"


def _checks_of(o: dict) -> list[dict]:
    t = o.get("type") or ("EntityDocument" if "layers" in o and "keys" in o else None)
    if not t:
        return [{"name": "type", "ok": False, "detail": "cannot tell what kind of object this is"}]
    ok, who = core.verify_object(o)
    checks = [{"name": "signature", "ok": ok, "detail": None if ok else who}]
    if ok and o.get("eid") and t in ("EntityDocument", "Declaration", "RecordEntry", "Withdrawal"):
        checks.append({"name": "signed by the EID", "ok": who == o["eid"], "detail": who})
    if t == "Declaration" and o.get("declaration_version") == "1.0":
        checks.append({"name": "declaration text hash", "ok": o.get("text_sha256") == core.DECLARATION_SHA256, "detail": o.get("text_sha256")})
    return checks


def _chain_checks(entries: list[dict], eid: str) -> list[dict]:
    """Record chain (spec 7.4): seq, prev, eid and signature of every entry. Redacted placeholders link by their hash."""
    bad, prev = [], None
    for e in entries:
        why = []
        if e.get("seq") != (prev["seq"] + 1 if prev else 1):
            why.append("seq breaks the sequence")
        if e.get("prev") != ((prev.get("hash") if prev.get("redacted") else core.canonical_hash(prev).hex()) if prev else None):
            why.append("prev hash breaks the chain")
        if not e.get("redacted"):
            if e.get("eid") != eid:
                why.append("eid mismatch")
            ok, err = core.verify_object(e)
            if not ok:
                why.append(f"signature: {err}")
        if why:
            bad.append({"name": f"record entry {e.get('seq')}", "ok": False, "detail": "; ".join(why)})
        prev = e
    return bad + [{"name": f"record chain ({len(entries)} entries)", "ok": not bad}]


# ponytail: no checkpoint or log-inclusion check here; `npx openentity verify <eid>` does those.
def _verify(args):
    t, reg = args.target, _registry(args)
    if t.startswith(("did:", "eid:")):
        ent = _get(reg, f"/v1/entities/{t}")
        eid = ent.get("document", {}).get("eid", t)
        checks = _checks_of(ent["document"])
        checks += _checks_of(ent["declaration"]) if ent.get("declaration") else [{"name": "declaration", "ok": False, "detail": "registry returned no Declaration"}]
        entries = []
        while page := _get(reg, f"/v1/entities/{eid}/record?after={entries[-1]['seq'] if entries else 0}")["entries"]:
            entries += page
        checks += _chain_checks(entries, eid)
    elif t.startswith(("http://", "https://")):
        checks = _checks_of(client._request(t))
    else:
        try:
            checks = _checks_of(json.loads(pathlib.Path(t).read_text()))
        except (OSError, ValueError) as e:
            raise CliError(EXIT_USAGE, f"cannot read {t}: {e}")
    ok = all(c["ok"] for c in checks)
    text = "\n".join(f"{'ok  ' if c['ok'] else 'FAIL'} {c['name']}" + (f": {c['detail']}" if c.get("detail") else "") for c in checks)
    return {"target": t, "ok": ok, "checks": checks}, f"{text}\n{'VERIFIED' if ok else 'VERIFICATION FAILED'}", EXIT_OK if ok else EXIT_VERIFY


def _run(args):
    """Returns (json, text) or (json, text, exit code)."""
    if args.cmd == "find":
        out = client.find(_registry(args), args.capability, args.q, args.alias_type, args.level)
        return out, _dump(out)
    if args.cmd in ("dispute", "present"):
        key = _load_key(args.eid)
        seed, reg = bytes.fromhex(key["seed_hex"]), _registry(args, key)
        out = (client.dispute(seed, args.subject, args.reason, args.statement, args.object_sha256, reg) if args.cmd == "dispute"
               else client.present(seed, args.audience, args.nonce, None if args.no_attestations else reg))
        return out, _dump(out)
    return {"adopt": _adopt, "whoami": _whoami, "self": _self, "record": _record, "verify": _verify, "withdraw": _withdraw}[args.cmd](args)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        try:
            out, text, *code = _run(args)
        except client.RegistryError as e:
            raise CliError(EXIT_NETWORK if e.status >= 500 else EXIT_REJECTED, str(e))
        except ValueError as e:  # the client rejecting a bad flag value
            raise CliError(EXIT_USAGE, str(e))
        except (urllib.error.URLError, TimeoutError) as e:
            raise CliError(EXIT_NETWORK, f"network error: {e}")
        except OSError as e:
            raise CliError(EXIT_STATE, str(e))
    except CliError as e:
        print(json.dumps({"error": str(e), "code": e.code}) if args.json else f"openentity: {e}", file=sys.stderr)
        return e.code
    print(_dump(out) if args.json else text)
    return code[0] if code else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
