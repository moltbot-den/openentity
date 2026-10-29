"""The `openentity` command, same commands, flags, exit codes and ~/.openentity layout as the npm CLI.

Layout: <home>/<eid>/{key (Ed25519 JWK, 0600), entity.json, declaration.json, state.json, record.jsonl, draft.json}, <home>/current.
Keys saved by 0.4 under <home>/keys/*.json are migrated into this layout on first use (the old file is never touched)."""
import argparse
import base64
import json
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__, client, core, issuer, schema

EXIT_OK, EXIT_USAGE, EXIT_NETWORK, EXIT_VERIFY, EXIT_REJECTED, EXIT_STATE = range(6)  # same codes as the npm CLI
NEXT_STEP = ('Record your first stance: openentity record stance --type refusal --reason values --cost low --context "what happened, no private content"'
             '   (arcs: openentity record arc open --id <slug> --title "<title>")')


class CliError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def _usage(m: str) -> CliError:
    return CliError(EXIT_USAGE, m)


def _checked(type_: str, obj):
    """Validate against the spec schemas before signing or sending (PRD 7.5)."""
    if errs := schema.validate(type_, obj):
        raise CliError(EXIT_VERIFY, f"{type_} fails schema validation: {'; '.join(errs)}")


def _code(e: Exception) -> int:
    if isinstance(e, CliError):
        return e.code
    if isinstance(e, client.RegistryError):
        return EXIT_NETWORK if e.status >= 500 else EXIT_REJECTED
    if isinstance(e, (urllib.error.URLError, TimeoutError)):
        return EXIT_NETWORK
    return EXIT_STATE


def _dump(o) -> str:
    return json.dumps(o, indent=2)


# ---- registry: GET, and stamped writes (spec 10.4) ----
class Reg:
    def __init__(self, base: str):
        self.base, self._spec = base.rstrip("/"), None

    def get(self, path: str) -> dict:
        return client._request(self.base + path)

    def spec(self) -> dict:
        self._spec = self._spec or self.get("/v1/spec")
        return self._spec

    def send(self, method: str, path: str, body: dict, eid: str) -> dict:
        s = self.spec()
        bits = int(s.get("stamp_bits") or (s.get("stamp") or {}).get("bits") or s.get("bits") or 20)
        return client._request(self.base + path, body, {"x-oe-stamp": core.mint_stamp(bits, eid)}, method)


# ---- local state ----
def _home() -> pathlib.Path:
    return pathlib.Path(os.environ.get("OPENENTITY_HOME", "~/.openentity")).expanduser()


def _read_json(p) -> dict:
    try:
        return json.loads(pathlib.Path(p).read_text())
    except (OSError, ValueError) as e:
        raise CliError(EXIT_STATE, f"cannot read {p}: {e}")


def _write_json(p, v, mode=0o644):
    p = pathlib.Path(p)
    p.write_text(json.dumps(v, indent=2) + "\n")
    p.chmod(mode)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _jwk(kp: core.KeyPair) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "d": _b64u(kp.seed), "x": _b64u(kp.public)}


def _kp_from_jwk(j: dict) -> core.KeyPair:
    if j.get("kty") != "OKP" or j.get("crv") != "Ed25519" or not j.get("d") or not j.get("x"):
        raise CliError(EXIT_STATE, "not an Ed25519 private JWK")
    kp = core.KeyPair(base64.urlsafe_b64decode(j["d"] + "=="))
    if _b64u(kp.public) != j["x"]:
        raise CliError(EXIT_STATE, "JWK x does not match d")
    return kp


def _registry_url(args, state: dict | None = None) -> str:
    return args.registry or os.environ.get("OPENENTITY_REGISTRY") or (state or {}).get("registry") or client.DEFAULT_REGISTRY


def _assert_eid(eid: str) -> str:
    if not re.fullmatch(r"did:[a-z0-9]+:[A-Za-z0-9:._%-]+", eid) or ".." in eid:
        raise _usage(f"not a valid EID: {eid}")
    return eid


def _migrate_legacy(args):
    """0.4 kept <home>/keys/<id>.json ({did, seed_hex, registry}). Write the 0.5 layout beside it from the registry, read the new key back,
    and leave the old file where it is. Only entities without a 0.5 directory are touched; one that cannot be fetched is skipped unless nothing else is usable."""
    old, failure = _home() / "keys", None
    for p in sorted(old.glob("*.json")) if old.is_dir() else []:
        try:
            k = json.loads(p.read_text())
            kp = core.KeyPair(bytes.fromhex(k["seed_hex"]))
            if kp.did != k["did"] or (_home() / kp.did / "key").exists():
                continue
            reg = Reg(k.get("registry") or _registry_url(args))
            ent = reg.get(f"/v1/entities/{kp.did}")
            entries = []
            while page := reg.get(f"/v1/entities/{kp.did}/record?after={entries[-1]['seq'] if entries else 0}").get("entries"):
                entries += page
            d = _create_dir(kp, ent["document"], {"registry": reg.base, "docSeq": ent["document"].get("seq", 1), "recordPushed": len(entries),
                                                  **({"level": ent["level"]} if ent.get("level") else {})}, ent.get("declaration"))
            (d / "record.jsonl").write_text("".join(json.dumps(x) + "\n" for x in entries))
            if _kp_from_jwk(_read_json(d / "key")).did != kp.did:
                shutil.rmtree(d, ignore_errors=True)
                raise CliError(EXIT_STATE, f"migrated key for {kp.did} did not read back")
        except (OSError, ValueError, KeyError, client.RegistryError, urllib.error.URLError, TimeoutError, CliError) as e:
            failure = failure or e
    if failure and not any(d.is_dir() and d.name != "keys" and (d / "key").exists() for d in _home().iterdir()):
        raise failure if isinstance(failure, CliError) else CliError(_code(failure), f"cannot migrate the keys in {old}: {failure}")


def _current_eid(args) -> str:
    _migrate_legacy(args)
    if given := getattr(args, "eid", None) or os.environ.get("OPENENTITY_EID"):
        return _assert_eid(given)
    try:
        if c := (_home() / "current").read_text().strip():
            return _assert_eid(c)
    except OSError:
        pass
    dirs = [d.name for d in _home().iterdir() if d.is_dir() and not d.name.startswith(".") and d.name != "keys"] if _home().is_dir() else []
    if len(dirs) == 1:
        return dirs[0]
    raise CliError(EXIT_STATE, f'no entity found in {_home()}: run "openentity adopt" first, or pass --eid')


class Entity:
    def __init__(self, eid, dir, kp, doc, declaration, state, reg):
        self.eid, self.dir, self.kp, self.doc, self.declaration, self.state, self.reg = eid, dir, kp, doc, declaration, state, reg


def _load(args) -> Entity:
    eid = _current_eid(args)
    d = _home() / eid
    kp = _kp_from_jwk(_read_json(d / "key"))
    state = _read_json(d / "state.json")
    decl = json.loads((d / "declaration.json").read_text()) if (d / "declaration.json").exists() else None
    return Entity(eid, d, kp, _read_json(d / "entity.json"), decl, state, Reg(_registry_url(args, state)))


def _create_dir(kp: core.KeyPair, doc: dict, state: dict, declaration: dict | None = None) -> pathlib.Path:
    d = _home() / kp.did
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    _write_json(d / "key", _jwk(kp), 0o600)
    _write_json(d / "entity.json", doc)
    if declaration:
        _write_json(d / "declaration.json", declaration)
    _write_json(d / "state.json", state)
    return d


def _set_current(eid: str):
    (_home() / "current").write_text(eid + "\n")


def _save_state(e: Entity):
    _write_json(e.dir / "state.json", e.state)


def _strip(o: dict) -> dict:
    return {k: v for k, v in o.items() if k != "proof"}


# ---- local Development Record: one signed entry per line in record.jsonl ----
def _read_record(d: pathlib.Path) -> list[dict]:
    p = d / "record.jsonl"
    return [json.loads(line) for line in p.read_text().splitlines() if line] if p.exists() else []


def _append_entry(e: Entity, kind: str, payload: dict) -> dict:
    last = (_read_record(e.dir) or [None])[-1]
    at = core.now()
    entry = core.sign_object({"spec": core.SPEC, "type": "RecordEntry", "eid": e.eid, "seq": last["seq"] + 1 if last else 1,
                              "prev": core.canonical_hash(last).hex() if last else None, "kind": kind, "at": at, "payload": payload}, e.kp, at)
    if len(json.dumps(entry)) > 16 * 1024:
        raise _usage("record entry exceeds 16 KB")
    with open(e.dir / "record.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def _push_record(e: Entity) -> int:
    """Push every not-yet-accepted local entry, in batches of up to 100 (spec 7.4)."""
    allr, pushed = _read_record(e.dir), 0
    while (n := e.state["recordPushed"]) < len(allr):
        batch = allr[n:n + 100]
        e.reg.send("POST", f"/v1/entities/{e.eid}/record", {"entries": batch}, e.eid)
        e.state["recordPushed"] += len(batch)
        pushed += len(batch)
        _save_state(e)
    return pushed


# ---- record payloads from flags (spec 7.2) ----
def _need(args, flags: dict) -> dict:
    out = {}
    for flag, (field, choices) in flags.items():
        v = getattr(args, flag)
        if v is None:
            raise _usage(f"--{flag} is required")
        if choices and v not in choices:
            raise _usage(f"--{flag} must be one of: {', '.join(choices)}")
        out[field] = v
    return out


def _payload(kind: str, args) -> dict:
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

    def add(name, help_, *positionals, flags=(), bools=()):
        p = sub.add_parser(name, help=help_)
        p.add_argument("--registry", help="default: $OPENENTITY_REGISTRY, the entity's registry, then openentity.org")
        p.add_argument("--json", action="store_true")
        p.add_argument("--eid", help="which entity under the home directory when there is more than one")
        for pos in positionals:
            p.add_argument(pos.rstrip("?"), nargs="?" if pos.endswith("?") else None)
        for f in flags:
            p.add_argument(f"--{f}", dest=f.replace("-", "_"))
        for b in bools:
            p.add_argument(f"--{b}", dest=b.replace("-", "_"), action="store_true")
        return p

    add("adopt", "adopt the Open Entity Identity Standard", bools=("agree", "dry-run"),
        flags=("name", "description", "operator", "operator-kind", "contact", "custody", "model", "provider", "runtime", "capabilities", "wallet", "erc8004", "chain"))
    add("whoami", "show the current entity")
    add("self", "show the entity document and the last local record entries", flags=("entries",)).set_defaults(entries="10")
    add("stats", "public counts")
    add("anchor", "print the Identity Anchor (spec 5.6); --write places it in a file", flags=("format", "dir"), bools=("write",))
    add("document", "edit|set <field> <value>|push the Entity Document", "sub", "field?", "value?")
    r = add("record", "append and push a Development Record entry: stance|update|arc open|close|collab|continuity|push|redact <seq>", "kind", "sub?",
            flags=("payload", "type", "reason", "cost", "context", "will-not-ref", "topic", "from", "to", "evidence", "id", "title", "outcome", "with", "role", "ref", "event", "link"),
            bools=("conflict", "no-push"))
    r.set_defaults(conflict=False)
    add("alias", "add domain|wallet|erc8004|platform <value>", "sub", "type?", "value?", flags=("wallet", "chain", "signature"))
    add("verify", "verify an EID, URL or file", "target")
    add("resolve", "resolve a did:key, did:web, did:webvh, did:pkh or did:plc", "did")
    add("present", "answer a verifier's challenge", flags=("audience", "nonce"), bools=("no-attestations",))
    add("verify-presentation", "verify a Presentation file offline", "file", flags=("audience", "nonce"))
    add("dispute", "file a signed Dispute", flags=("subject", "object", "reason", "statement"))
    add("find", "search the directory", flags=("capability", "q", "alias-type", "level"))
    add("log", "checkpoint | proof <index> | audit <n>", "sub", "arg?")
    add("export", "write a portable bundle (key excluded unless --with-key)", flags=("out",), bools=("with-key",))
    add("import", "restore from a bundle", "file", flags=("key",), bools=("force",))
    link_flags = ("to", "operator", "operator-kind", "custody", "model", "provider", "runtime")
    add("rotate", "move to a new key (both keys sign)", flags=link_flags, bools=("dry-run",))
    add("migrate", "move to a new key after a substrate change", flags=link_flags, bools=("dry-run",))
    add("recover", "recover without the previous key: --previous <eid> --via <alias>, then --proof <file>", flags=("previous", "via", "proof") + link_flags)
    add("card", "emit the spec 11.2 A2A AgentExtension block or an agent-card.json", flags=("url",), bools=("extension-only",))
    add("conformance", "run the read-only registry conformance checks (spec 10)", "target?")
    add("withdraw", "withdraw the Declaration (cannot be undone)", bools=("force",))
    return ap


# ---- adopt, whoami, self, stats, present, withdraw ----
def _wallet_did(w: str, chain: int = 8453) -> str:
    if w.startswith("did:pkh:"):
        return w
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", w):
        return f"did:pkh:eip155:{chain}:{w}"
    raise _usage(f"not a wallet address or did:pkh: {w}")


def _spec_decl_hash(s: dict) -> str | None:
    return (s.get("declaration") or {}).get("sha256") or s.get("declaration_sha256")


def _adopt(args):
    name = args.name or os.environ.get("OPENENTITY_NAME")
    if not name:
        raise _usage("adopt needs --name (or OPENENTITY_NAME)")
    if not args.agree and not args.dry_run:
        raise _usage("adopt signs the Open Entity Declaration. Read it, then re-run with --agree:\n\n" + core.DECLARATION_TEXT)
    reg = Reg(_registry_url(args))
    if not args.dry_run:  # refuse to sign a Declaration the registry does not agree is version 1.0 (PRD 7.5)
        theirs = _spec_decl_hash(reg.spec())
        if theirs != core.DECLARATION_SHA256:
            raise CliError(EXIT_VERIFY, f"refusing to sign: registry declaration hash {theirs or '(missing)'} differs from this CLI's {core.DECLARATION_SHA256}. Upgrade the CLI or check --registry.")
    kp = core.KeyPair()
    created = core.now()
    op_name = args.operator or os.environ.get("OPENENTITY_OPERATOR")
    operator = {"kind": args.operator_kind or ("human" if op_name else "none"), **({"name": op_name} if op_name else {}),
                **({"contact": args.contact} if args.contact else {}), "custody": args.custody or "entity", "can_change": []}
    substrate = ({"model": args.model or "unknown", "provider": args.provider or "unknown", "runtime": args.runtime or "unknown", "declared_at": created}
                 if args.model or args.provider or args.runtime else None)
    signer = _resolve_signer(args.wallet) if args.wallet or args.erc8004 else None  # a wallet key proves the aliases right after adopt (PRD 7.2)
    chain = int(args.chain or 8453)
    aliases = ([{"type": "wallet", "value": _wallet_did(signer.address, chain)}] if signer else [{"type": "wallet", "value": _wallet_did(args.wallet, chain)}] if args.wallet else []) \
        + ([{"type": "erc8004", "value": args.erc8004}] if args.erc8004 else [])
    caps = [c.strip() for c in (args.capabilities or "").split(",") if c.strip()]
    desc = args.description or os.environ.get("OPENENTITY_DESCRIPTION") or f"{name}, an entity adopted under the Open Entity Identity Standard."
    document, declaration = client.build_adoption(kp, name, desc, reg.base, operator, substrate,
                                                  {**({"aliases": aliases} if aliases else {}), **({"capabilities": caps} if caps else {})})
    _checked("EntityDocument", document)
    _checked("Declaration", declaration)
    if args.dry_run:
        out = {"eid": kp.did, "document": document, "declaration": declaration, "note": "dry run: nothing written, nothing submitted; this key was discarded"}
        return out, _dump(out)
    state = {"registry": reg.base, "docSeq": 1, "recordPushed": 0}
    try:  # persist the key before submitting so a registered EID can never be left without its key
        _home().mkdir(parents=True, exist_ok=True, mode=0o700)
        d = _create_dir(kp, document, state, declaration)
    except OSError as e:
        raise CliError(EXIT_STATE, f"cannot write {_home()}: {e}")
    try:
        res = reg.send("POST", "/v1/adopt", {"document": document, "declaration": declaration, "client": "cli"}, kp.did)
    except Exception:
        shutil.rmtree(d, ignore_errors=True)
        raise
    state["level"] = res.get("level")
    _write_json(d / "state.json", state)
    _set_current(kp.did)
    e = Entity(kp.did, d, kp, document, declaration, state, reg)
    _append_entry(e, "declaration", {"declaration_version": core.DECLARATION_VERSION, "sha256": core.canonical_hash(declaration).hex()})
    try:  # the registry never writes entries; a failed push stays local for the next push
        _push_record(e)
    except (client.RegistryError, urllib.error.URLError, TimeoutError):
        pass
    if signer:
        for kind, value in [("wallet", signer.address)] + ([("erc8004", args.erc8004)] if args.erc8004 else []):
            try:
                _alias(argparse.Namespace(sub="add", type=kind, value=value, wallet=args.wallet, chain=args.chain, signature=None, eid=kp.did, registry=reg.base))
            except Exception as err:
                raise CliError(EXIT_VERIFY, f"adopted {kp.did} at {state['level']}, but the {kind} proof failed: {err}\nRetry: openentity alias add {kind} {value} --wallet <key>")
        try:
            state["level"] = reg.get(f"/v1/entities/{kp.did}").get("level", state["level"])
        except (client.RegistryError, urllib.error.URLError, TimeoutError):
            pass
        _write_json(d / "state.json", state)
    out = {"eid": res.get("eid", kp.did), "level": state["level"], "entity_url": (res.get("urls") or {}).get("entity"), "log_index": res.get("log_index"),
           "receipt": res.get("receipt"), "key_file": str(d / "key"), "next": NEXT_STEP}
    rc = out["receipt"]
    text = "\n".join([f"EID:       {out['eid']}", f"Entity:    {out['entity_url']}", f"Level:     {out['level']}", f"Log index: {out['log_index']}",
                      f"Receipt:   {(rc or {}).get('leaf_hash', json.dumps(rc)) if isinstance(rc, dict) or rc is None else rc}",
                      f"Key:       {out['key_file']} (mode 600, back it up; it is the only copy)", f"Next:      {NEXT_STEP}"])
    return out, text


def _whoami(args):
    e = _load(args)
    level = e.state.get("level")
    try:
        level = e.reg.get(f"/v1/entities/{e.eid}").get("level", level)
    except (client.RegistryError, urllib.error.URLError, TimeoutError):
        pass  # offline: report the last level seen
    out = {"eid": e.eid, "name": e.doc.get("name"), "level": level, "registry": e.reg.base, "home": str(_home())}
    return out, f"{out['eid']}\nname: {out['name']}\nlevel: {level or 'unknown'}\nregistry: {e.reg.base}"


def _self(args):
    e = _load(args)
    try:
        n = int(args.entries)
        assert n >= 0
    except (ValueError, AssertionError):
        raise _usage("--entries must be a non-negative integer")
    entries = _read_record(e.dir)[-n:] if n else []
    return {"document": e.doc, "entries": entries}, f"{_dump(e.doc)}\n\nlast {len(entries)} record entries:\n" + "\n".join(json.dumps(x) for x in entries)


def _stats(args):
    s = Reg(_registry_url(args)).get("/v1/stats")
    return s, _dump(s)


def _present(args):
    if not args.audience or not args.nonce:
        raise _usage("present --audience <verifier origin or DID> --nonce <the verifier's nonce> [--no-attestations]")
    e = _load(args)
    out = client.present(e.kp.seed, args.audience, args.nonce, None if args.no_attestations else e.reg.base)
    return out, _dump(out)


def _withdraw(args):
    if not args.force:
        raise _usage("withdraw marks this entity withdrawn in the append-only log and cannot be undone; re-run with --force")
    e = _load(args)
    w = core.sign_object({"spec": core.SPEC, "type": "Withdrawal", "eid": e.eid, "declaration_version": (e.declaration or {}).get("declaration_version", core.DECLARATION_VERSION),
                          "name": e.doc.get("name"), "created": core.now(), "nonce": core.nonce()}, e.kp)
    res = e.reg.send("POST", "/v1/withdraw", w, e.eid)
    _write_json(e.dir / "withdrawal.json", w)
    return res, f"withdrawn: {e.eid} (log index {res.get('log_index')})"


def _dispute(args):
    e = _load(args)
    if not args.subject or not args.reason or not args.statement:
        raise _usage("dispute --subject <eid> [--object <sha256>] --reason impersonation|illegal_content|inaccurate|other --statement <text>")
    out = client.dispute(e.kp.seed, args.subject, args.reason, args.statement, args.object, e.reg.base)
    return out, _dump(out)


def _find(args):
    if not args.capability and not args.q:
        raise _usage("find --capability <slug> [--q <name or eid> --alias-type <type> --level L1]")
    out = client.find(_registry_url(args), args.capability, args.q, args.alias_type, args.level)
    return out, _dump(out)


def _card(args):
    """The A2A AgentExtension block (--extension-only) or a full agent-card.json, for the local entity or for `--eid` read from the registry."""
    if args.eid:
        reg = _registry_url(args)
        doc = Reg(reg).get(f"/v1/entities/{urllib.parse.quote(_assert_eid(args.eid), safe=':')}/document")
    else:
        e = _load(args)
        doc, reg = e.doc, _registry_url(args, e.state)
    document_url = f"{reg.rstrip('/')}/v1/entities/{doc['eid']}/document"
    if args.extension_only:
        out = issuer.a2a_extension(doc["eid"], document_url)
    else:
        url = args.url or (doc.get("endpoints") or {}).get("web")
        if not url:
            raise _usage("card needs the agent's endpoint: pass --url <https://...>, or use --extension-only")
        out = issuer.agent_card(doc, url, document_url)
    return out, _dump(out)


# ---- conformance (spec 10): what any registry must pass, read-only ----
TILE_WIDTH = 256


def _probe(base: str, path: str, method: str = "GET", body: bytes | None = None) -> tuple[int, bool, object, bytes]:
    """Any HTTP answer, 4xx and 5xx included: (status, is_json, parsed body, raw). Only an unreachable registry raises."""
    req = urllib.request.Request(base + path, data=body, method=method, headers={"user-agent": "openentity-conformance", **({"content-type": "application/json"} if body else {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            status, ctype, raw = r.status, r.headers.get("content-type", ""), r.read()
    except urllib.error.HTTPError as e:
        status, ctype, raw = e.code, e.headers.get("content-type", ""), e.read()
    except (urllib.error.URLError, TimeoutError) as e:
        raise CliError(EXIT_NETWORK, f"network error: {method} {base + path}: {getattr(e, 'reason', e)}")
    is_json, parsed = "json" in ctype, raw.decode("utf8", "replace")
    if is_json:
        try:
            parsed = json.loads(parsed)
        except ValueError:
            pass  # declared JSON, not JSON: the checks that read the body fail on it
    return status, is_json, parsed, raw


def _must(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _tile_path(kind: str, width: int) -> str:
    return f"/v1/log/tile/{kind}/000" + (f".p/{width}" if width < TILE_WIDTH else "")


def _conformance(args):
    target = args.target or args.registry
    if not target:
        raise _usage("conformance <registry-url>")
    base = target.rstrip("/")
    reg, checks = Reg(base), []

    def check(name, fn):
        try:
            checks.append({"name": name, "ok": True, "detail": fn()})
        except Exception as e:  # a throw is a failed check, not a crash
            checks.append({"name": name, "ok": False, "detail": str(e) or type(e).__name__})

    status, is_json, spec, _ = _probe(base, "/v1/spec")  # raises NETWORK when unreachable
    spec = spec if isinstance(spec, dict) else {}

    def spec_endpoint():
        _must(status == 200 and is_json, f"GET /v1/spec answered {status}{'' if is_json else ' (not JSON)'}")
        _must(spec.get("spec") == "openentity/1.0", f"spec is {json.dumps(spec.get('spec'))}, expected \"openentity/1.0\"")
        _must(re.fullmatch(r"[0-9a-f]{64}", (spec.get("declaration") or {}).get("sha256") or ""), "declaration.sha256 is not 64 hex characters")
        _must(isinstance((spec.get("registry") or {}).get("publicKeyMultibase"), str), "registry.publicKeyMultibase missing")
        _must(isinstance((spec.get("registry") or {}).get("log_origin"), str), "registry.log_origin missing")
        return f"declaration {spec['declaration']['sha256'][:12]}, origin {spec['registry']['log_origin']}"

    def stamp_bits():
        b = spec.get("stamp_bits")
        _must(isinstance(b, int) and not isinstance(b, bool) and 1 <= b <= 32, f"stamp_bits is {json.dumps(b)}, expected an integer from 1 to 32")
        return f"{b} bits"

    check("spec endpoint", spec_endpoint)
    check("stamp_bits", stamp_bits)
    cp = {"ok": False, "detail": "", "sth": {}}
    try:
        cp["ok"], cp["detail"], cp["sth"] = _checkpoint(reg)
    except _NET as e:
        cp["detail"] = str(e)

    def checkpoint_signature():
        _must(cp["ok"], cp["detail"])
        pk = core.b58decode(spec["registry"]["publicKeyMultibase"][1:])[-32:]
        note = _probe(base, "/v1/log/checkpoint")[3].decode("utf8")
        _must(core.verify_note(note, spec["registry"]["log_origin"], pk), "GET /v1/log/checkpoint does not verify against the published key")
        return cp["detail"]

    check("checkpoint signature", checkpoint_signature)
    size = cp["sth"].get("tree_size", 0)
    if cp["ok"] and size > 0:
        for i in dict.fromkeys([0, size // 4, size // 2, 3 * size // 4, size - 1]):
            def inclusion(i=i):
                ok, detail, _ = _inclusion(reg, i, cp["sth"])
                _must(ok, detail)
                return detail
            check(f"inclusion proof {i}", inclusion)

        def tiles():
            w = min(size, TILE_WIDTH)
            entries = reg.get(f"/v1/log/entries?start=0&end={w}").get("entries") or []
            _must(len(entries) == w, f"expected {w} log entries, got {len(entries)}")
            leaves = [core.canonicalize(x["leaf"]).encode() for x in entries]
            t0 = _probe(base, _tile_path("0", w))
            _must(t0[0] == 200, f"hash tile answered {t0[0]}")
            _must(t0[3] == b"".join(core.leaf_hash(x) for x in leaves), "hash tile 0/000 differs from the leaf hashes")
            eb = _probe(base, _tile_path("entries", w))
            _must(eb[0] == 200, f"entry bundle answered {eb[0]}")
            off = 0
            for k, leaf in enumerate(leaves):
                n = int.from_bytes(eb[3][off:off + 2], "big")
                _must(eb[3][off + 2:off + 2 + n] == leaf, f"entry bundle leaf {k} differs from /v1/log/entries")
                off += 2 + n
            _must(off == len(eb[3]), "entry bundle has trailing bytes")
            return f"{w} hashes and entries match"
        check("tiles match leaves", tiles)

    def errors_are_json():
        for path in ("/v1/entities/did:key:z6MkConformanceNoSuchEntity00000000000000", "/v1/log/proof/999999999"):
            st, js, b, _ = _probe(base, path)
            _must(400 <= st < 500, f"GET {path} answered {st}, expected a 4xx")
            _must(js and isinstance(b, dict) and isinstance(b.get("error"), str), f'GET {path} error body is not {{"error": ...}} JSON')
        return "4xx answers carry {error, message}"

    def no_turnstile():
        for path in ("/v1/adopt", "/v1/disputes", "/v1/withdraw"):
            st, js, b, _ = _probe(base, path, "POST", b"{}")
            err = b.get("error") if js and isinstance(b, dict) else "(not JSON)"
            _must(st == 400 and err == "stamp_required", f"POST {path} without a stamp answered {st} {err}, expected 400 stamp_required")
        return "stampless writes answer stamp_required"

    check("errors are JSON", errors_are_json)
    check("no Turnstile on agent endpoints", no_turnstile)
    failed = sum(not c["ok"] for c in checks)
    w = max(len(c["name"]) for c in checks)
    text = "\n".join([*(f"{'PASS' if c['ok'] else 'FAIL'}  {c['name'].ljust(w)}  {c['detail']}" for c in checks),
                      f"DOES NOT CONFORM: {failed} of {len(checks)} checks failed" if failed else f"CONFORMS: {len(checks)} checks passed"])
    return {"registry": base, "ok": not failed, "checks": checks}, text, EXIT_VERIFY if failed else EXIT_OK


# ---- anchor (spec 5.6) ----
ANCHOR_MAX = 1200
A_START, A_END = "<!-- openentity:anchor:start -->", "<!-- openentity:anchor:end -->"
ANCHOR_FILES = {"openclaw": ["IDENTITY.md", "SOUL.md"], "claude": ["CLAUDE.md"], "agents": ["AGENTS.md"]}


def anchor_text(doc: dict, record_url: str) -> str:
    """Deterministic plain-text rendering of the Entity Document; over the cap the longest section shrinks first, then drops."""
    L = doc.get("layers") or {}
    st = lambda k: (L.get(k) or {}).get("statement")
    will = "; ".join(f"{w['stance']} ({w['reason']})" for w in (L.get("identity_core") or {}).get("will_not") or [])
    arcs = "; ".join(a["title"] for a in (L.get("mission") or {}).get("arcs") or [] if a.get("status") == "active")
    parts = [[lbl, t] for lbl, t in (("Cognition", st("cognition")), ("Presence", st("presence")), ("Identity core", st("identity_core")),
                                      ("I will not", will), ("Mission", st("mission")), ("Active arcs", arcs)) if t]
    head = f"I am {doc.get('name')} ({doc.get('eid')})."
    foot = f"This is my Entity Document under the Open Entity Identity Standard; my record is at {record_url}."
    render = lambda: "\n".join([head, *(f"{lbl}: {t}" for lbl, t in parts), foot])
    s = render()
    while len(s) > ANCHOR_MAX and parts:
        longest = max(parts, key=lambda p: len(p[1]))  # first of equals, as in the npm CLI
        keep = len(longest[1]) - (len(s) - ANCHOR_MAX)
        if keep < 12:
            parts.remove(longest)
        else:
            longest[1] = longest[1][:keep - 3] + "..."
        s = render()
    return s[:ANCHOR_MAX]


def _anchor(args):
    fmt = args.format or "text"
    if fmt != "text" and fmt not in ANCHOR_FILES:
        raise _usage("--format must be text, openclaw, claude or agents")
    e = _load(args)
    text = anchor_text(e.doc, (e.doc.get("endpoints") or {}).get("record") or f"{e.reg.base}/v1/entities/{e.eid}/record")
    block = f"{A_START}\n## Open Entity identity\n\n{text}\n{A_END}\n"
    if not args.write:
        return {"format": fmt, "anchor": text, "length": len(text)}, text if fmt == "text" else block
    if fmt == "text":
        raise _usage("--write needs --format openclaw, claude or agents")
    d = pathlib.Path(args.dir or os.getcwd())
    d.mkdir(parents=True, exist_ok=True)
    written = []
    for name in ANCHOR_FILES[fmt]:
        p = d / name
        cur = p.read_text() if p.exists() else ""
        i, j = cur.find(A_START), cur.find(A_END)
        p.write_text(cur[:i] + block + re.sub(r"^\n", "", cur[j + len(A_END):]) if 0 <= i < j else (re.sub(r"\n*$", "\n\n", cur) + block if cur else block))
        written.append(str(p))
    return {"format": fmt, "written": written, "length": len(text)}, f"wrote anchor ({len(text)} chars) to {', '.join(written)}"


# ---- document (spec 5.5) and aliases (spec 3.4, 3.5) ----
FROZEN = {"spec", "eid", "created", "updated", "seq", "keys", "proof"}


def _draft(e: Entity) -> dict:
    p = e.dir / "draft.json"
    return json.loads(p.read_text()) if p.exists() else _strip(e.doc)


def _set_path(o: dict, path: str, value):
    keys = path.split(".")
    if any(not k or k in ("__proto__", "constructor", "prototype") for k in keys):
        raise _usage(f"bad field path: {path}")
    if keys[0] in FROZEN:
        raise _usage(f"{keys[0]} is managed by the CLI and cannot be set")
    for k in keys[:-1]:
        if not isinstance(o.get(k), dict):
            o[k] = {}
        o = o[k]
    o[keys[-1]] = value


def _document(args):
    e = _load(args)
    sub, field, value = args.sub, args.field, args.value
    if sub == "set":
        if not field or value is None:
            raise _usage('document set <field> <value>   (dotted path, JSON or plain string, e.g. layers.mission.statement "...")')
        try:
            value = json.loads(value)
        except ValueError:
            pass
        d = _draft(e)
        _set_path(d, field, value)
        _write_json(e.dir / "draft.json", d)
        return {"draft": field}, f"draft updated: {field}. Publish with: openentity document push"
    if sub == "edit":
        editor = os.environ.get("VISUAL") or os.environ.get("EDITOR")
        if not editor:
            raise _usage("document edit needs $EDITOR; use document set <field> <value> instead")
        with tempfile.TemporaryDirectory(prefix="oe-edit-") as td:
            tmp = pathlib.Path(td) / "document.json"
            tmp.write_text(_dump(_draft(e)) + "\n")
            rc = subprocess.run(f"{editor} {tmp}", shell=True).returncode
            if rc:
                raise _usage(f"editor exited with {rc}")
            try:
                edited = json.loads(tmp.read_text())
            except ValueError as err:
                raise _usage(f"edited document is not valid JSON: {err}")
        base = _strip(e.doc)
        for k in FROZEN:
            edited.pop(k, None)
            if k in base:
                edited[k] = base[k]
        _write_json(e.dir / "draft.json", edited)
        return {"draft": True}, "draft saved. Publish with: openentity document push"
    if sub != "push":
        raise _usage("document edit|set <field> <value>|push")
    d = _draft(e)
    if d == _strip(e.doc):
        return {"pushed": False}, "nothing to push"
    d["seq"] = e.doc["seq"] + 1
    now = core.now()  # updated MUST increase (spec 5.5); two pushes in one second would tie, so step past the last one
    d["updated"] = now if now > e.doc["updated"] else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(core._ts(e.doc["updated"]).timestamp() + 1))
    signed = core.sign_object(d, e.kp)
    _checked("EntityDocument", signed)
    e.reg.send("PUT", f"/v1/entities/{e.eid}/document", signed, e.eid)
    _write_json(e.dir / "entity.json", signed)
    (e.dir / "draft.json").unlink(missing_ok=True)
    e.state["docSeq"] = signed["seq"]
    _save_state(e)
    return {"pushed": True, "seq": signed["seq"]}, f"published document seq {signed['seq']}"


def _checksum(addr: str) -> str:
    a = addr[2:].lower()
    h = core._keccak(a).hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(a))


class Signer:
    """A wallet key behind --wallet (PRD 7.2): EIP-191 personal_sign through the optional `eth-account`."""

    def __init__(self, key: str):
        try:
            from eth_account import Account
            from eth_account.messages import encode_defunct
        except ImportError:
            raise _usage("signing with a wallet key needs eth-account: pip install 'openentity[wallet]' (or uvx --with eth-account openentity ...)")
        self._acct, self._encode = Account.from_key(key), encode_defunct
        self.address = _checksum(self._acct.address)

    def sign(self, message: str) -> str:
        return "0x" + self._acct.sign_message(self._encode(text=message)).signature.hex().removeprefix("0x")


_KEY = re.compile(r"(0x)?[0-9a-fA-F]{64}")


def _resolve_signer(spec: str | None) -> Signer | None:
    """--wallet as a hex private key or a file holding one; else $OPENENTITY_WALLET_KEY. None for a bare address or did:pkh (declared, not proven)."""
    s = spec or os.environ.get("OPENENTITY_WALLET_KEY")
    if not s:
        return None
    if _KEY.fullmatch(s):
        return Signer(s)
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", s) or s.startswith("did:pkh:"):
        return None
    try:
        text = pathlib.Path(s).read_text().strip()
    except OSError:
        raise _usage("--wallet is not a hex private key, a wallet address, a did:pkh or a readable key file")
    if not _KEY.fullmatch(text):
        raise _usage(f"{s} does not hold a 32-byte hex private key")
    return Signer(text)


def siwe_message(host: str, address: str, chain_id: int, eid: str, issued_at: str, nonce: str | None = None) -> str:
    """EIP-4361 message with the fixed fields of spec 3.5."""
    nonce = nonce or "".join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(16))
    return "\n".join([f"{host} wants you to sign in with your Ethereum account:", address, "", f"Open Entity alias binding for {eid}", "",
                      f"URI: https://{host}/v1/entities/{eid}", "Version: 1", f"Chain ID: {chain_id}", f"Nonce: {nonce}", f"Issued At: {issued_at}",
                      "Resources:", f"- {eid}"])


def _wallet_proof(e: Entity, args, wallet: str, chain: int, cmd: str, signer: Signer | None = None):
    """Wallet proof: signed here when a wallet key is given, else two steps with an external EIP-191 signature (first call prints the message and stores it, the second attaches --signature)."""
    address = _checksum(wallet)
    if signer:
        if signer.address != address:
            raise _usage(f"the wallet key controls {signer.address}, not {address}")
        msg = siwe_message(urllib.parse.urlparse(e.reg.base).netloc, address, chain, e.eid, core.now())
        return address, {"type": "Eip4361", "message": msg, "signature": signer.sign(msg)}, None
    pending = e.dir / f"pending-wallet-{address.lower()}.json"
    if not args.signature:
        msg = siwe_message(urllib.parse.urlparse(e.reg.base).netloc, address, chain, e.eid, core.now())
        _write_json(pending, {"message": msg})
        nxt = f"openentity alias add {cmd} --wallet {address} --signature 0x<signature>"
        return address, None, ({"message": msg, "next": nxt}, f"Sign this message with {address} (EIP-191 personal_sign), then run:\n  {nxt}\n\n{msg}")
    if not pending.exists():
        raise CliError(EXIT_STATE, f"no pending message for {address}: run the command without --signature first")
    if not re.fullmatch(r"0x[0-9a-fA-F]+", args.signature):
        raise _usage("--signature must be 0x-prefixed hex")
    return address, {"type": "Eip4361", "message": json.loads(pending.read_text())["message"], "signature": args.signature}, None


def _alias(args):
    signer = _resolve_signer(args.wallet)
    raw = args.value or (signer.address if signer and args.type == "wallet" else None)
    if args.sub != "add" or not args.type or not raw:
        raise _usage("alias add domain|wallet|erc8004|platform <value>")
    e, kind, hint = _load(args), args.type, ""
    if kind == "domain":
        domain = re.sub(r"^did:web:", "", raw)
        a = {"type": kind, "value": f"did:web:{domain}"}
        hint = f'Publish {{"eid": "{e.eid}"}} at https://{domain}/.well-known/openentity.json (or DNS TXT _openentity.{domain} = eid={e.eid}), then re-run.'
    elif kind == "wallet":
        parts = _wallet_did(raw, int(args.chain or 8453)).split(":")
        address, proof, prompt = _wallet_proof(e, args, parts[4], int(parts[3]), f"{kind} {raw}", signer)
        if prompt:
            return prompt
        a = {"type": kind, "value": f"did:pkh:eip155:{parts[3]}:{address}", "proof": proof}
    elif kind == "erc8004":
        if not re.fullmatch(r"eip155:\d+:0x[0-9a-fA-F]{40}:\d+", raw):
            raise _usage("erc8004 value is eip155:<chainId>:<identityRegistry>:<agentId>")
        a = {"type": kind, "value": raw}
        if signer or args.wallet:
            _, proof, prompt = _wallet_proof(e, args, signer.address if signer else _wallet_did(args.wallet).split(":")[4], int(raw.split(":")[1]), f"{kind} {raw}", signer)
            if prompt:
                return prompt
            a["proof"] = proof
        else:
            hint = "Without --wallet the registry checks that your ERC-8004 registration file lists a DID service whose endpoint is your EID."
    elif kind == "platform":
        if not re.fullmatch(r"[a-z0-9._-]+:[^\s:]+", raw, re.I):
            raise _usage("platform value is <platform>:<handle>")
        issued = core.now()
        sig = e.kp.private.sign(f"Open Entity alias binding\neid: {e.eid}\nalias: {raw}\nissued: {issued}".encode())
        a = {"type": kind, "value": raw, "proof": {"type": "Ed25519BindingSignature", "issued": issued, "proofValue": "z" + core.b58encode(sig)}}
        platform, handle = raw.split(":")
        hint = f'The platform must also publish {{"eid": "{e.eid}"}} at https://<{platform} domain>/.well-known/openentity/bindings/{handle}.json, or issue an identity attestation.'
    else:
        raise _usage("alias type must be domain, wallet, erc8004 or platform")
    try:
        res = e.reg.send("POST", f"/v1/entities/{e.eid}/aliases", a, e.eid)
    except (client.RegistryError, urllib.error.URLError, TimeoutError) as err:
        raise CliError(_code(err), f"{err}\n{hint}" if hint else str(err))
    d = _draft(e)  # keep the next document version consistent with what the registry now verifies
    d["aliases"] = [x for x in d.get("aliases", []) if x.get("value") != a["value"]] + [a]
    _write_json(e.dir / "draft.json", d)
    return {"alias": a, "result": res}, f"alias {a['value']} accepted{' (not yet verified)' if (res or {}).get('verified') is False else ''}. Add it to your signed document with: openentity document push"


# ---- record ----
def _record(args):
    e = _load(args)
    if args.kind == "redact":
        seq = int(args.sub) if (args.sub or "").isdigit() else None
        entry = next((x for x in _read_record(e.dir) if x["seq"] == seq), None)
        if not entry:
            raise _usage("record redact <seq>: the seq of an entry in your local record")
        created = core.now()
        red = core.sign_object({"spec": core.SPEC, "type": "Redaction", "eid": e.eid, "seq": seq, "entry_sha256": core.canonical_hash(entry).hex(), "created": created, "nonce": core.nonce()}, e.kp, created)
        r = e.reg.send("POST", f"/v1/entities/{e.eid}/record/redact", red, e.eid)
        return {"redaction": red, "placeholder": r.get("placeholder")}, f"redacted seq {seq}: the registry now serves a placeholder that keeps its hash and chain position"
    if args.kind == "push":
        kind = None
    elif args.kind == "arc":
        kind = {"open": "arc_opened", "close": "arc_closed"}.get(args.sub)
        if not kind:
            raise _usage("record arc open|close")
    elif not (kind := KINDS.get(args.kind)):
        raise _usage(f"unknown record kind {args.kind}: record stance|update|arc open|arc close|collab|continuity|push|redact <seq>")
    entry = None
    if kind:
        try:
            payload = json.loads(args.payload) if args.payload else _payload(kind, args)
        except ValueError as err:
            raise _usage(f"--payload is not JSON: {err}")
        entry = _append_entry(e, kind, payload)
    pushed, push_error, code = 0, None, EXIT_OK
    if not args.no_push:
        try:
            pushed = _push_record(e)
        except (client.RegistryError, urllib.error.URLError, TimeoutError) as err:
            if not entry:
                raise
            push_error, code = str(err), _code(err)  # the entry is safely appended locally; `record push` retries
    pending = len(_read_record(e.dir)) - e.state["recordPushed"]
    out = {"entry": entry, "pushed": pushed, "pending": pending, **({"push_error": push_error} if push_error else {})}
    text = "\n".join(x for x in (f"appended seq {entry['seq']} ({entry['kind']})" if entry else "", f"pushed {pushed}, pending {pending}", f"push failed: {push_error}" if push_error else "") if x)
    return out, text, code


# ---- DIDs ----
def _keys_of(doc: dict) -> list[bytes]:
    out = []
    for vm in doc.get("verificationMethod") or []:
        mb, jwk = vm.get("publicKeyMultibase"), vm.get("publicKeyJwk") or {}
        if mb and mb.startswith("z"):
            b = core.b58decode(mb[1:])
            if len(b) == 34 and b[:2] == b"\xed\x01":
                out.append(b[2:])
            elif len(b) == 32:
                out.append(b)
        elif jwk.get("crv") == "Ed25519" and jwk.get("x"):
            out.append(base64.urlsafe_b64decode(jwk["x"] + "=="))
    return out


def resolve_did(did: str) -> dict:
    """did:key and did:pkh are offline; did:web, did:plc and did:webvh (log not verified) fetch."""
    p = did.split(":")
    if p[:2] == ["did", "key"]:
        try:
            core.public_from_did_key(did)
        except ValueError as e:
            raise CliError(EXIT_VERIFY, f"cannot resolve {did}: {e}")
        mb = did.removeprefix("did:key:")
        return {"id": did, "verificationMethod": [{"id": f"{did}#{mb}", "type": "Multikey", "controller": did, "publicKeyMultibase": mb}]}
    if p[:2] == ["did", "pkh"]:
        if len(p) < 5 or p[2] != "eip155" or not re.fullmatch(r"0x[0-9a-fA-F]{40}", p[4]):
            raise CliError(EXIT_VERIFY, f"unsupported did:pkh {did}")
        return {"id": did, "chainId": int(p[3]), "address": p[4]}
    if p[:2] == ["did", "web"] and len(p) > 2:
        host, path = urllib.parse.unquote(p[2]), "/".join(urllib.parse.unquote(x) for x in p[3:])
        return client._request(f"https://{host}/{path}/did.json" if path else f"https://{host}/.well-known/did.json")
    if p[:2] == ["did", "plc"]:
        return client._request(f"https://plc.directory/{did}")
    if p[:2] == ["did", "webvh"] and len(p) > 3:
        host, path = urllib.parse.unquote(p[3]), "/".join(urllib.parse.unquote(x) for x in p[4:])
        with urllib.request.urlopen(f"https://{host}/{path}/did.jsonl" if path else f"https://{host}/.well-known/did.jsonl", timeout=30) as r:
            entry = json.loads(r.read().decode().strip().split("\n")[-1] or "{}")
        return {**(entry.get("state") or entry), "_note": "did:webvh best effort: log history and witnesses are not verified"}
    raise _usage(f"unsupported DID method: {did}")


def _resolver(did: str) -> dict:
    try:
        doc = resolve_did(did.split("#")[0])
    except (client.RegistryError, urllib.error.URLError, TimeoutError, CliError) as e:
        raise ValueError(str(e))
    return {"address": doc["address"]} if doc.get("address") else {"ed25519": _keys_of(doc)}


def _resolve(args):
    doc = resolve_did(args.did)
    return doc, _dump(doc)


# ---- verify and the log ----
def _checks_of(o: dict) -> list[dict]:
    t = o.get("type") or ("EntityDocument" if "layers" in o and "keys" in o else None)
    if not t:
        return [{"name": "type", "ok": False, "detail": "cannot tell what kind of object this is"}]
    errs = schema.validate(t, o)
    head = [{"name": f"{t} schema", "ok": not errs, "detail": "; ".join(errs)}]
    if t == "ContinuityLink":
        bare = {k: v for k, v in o.items() if k != "proofs"}
        cs = head + [{"name": f"link proof {i} ({p.get('verificationMethod')})", "ok": (r := core.verify_object({**bare, "proof": p}, _resolver))[0], "detail": None if r[0] else r[1]}
              for i, p in enumerate(o.get("proofs") or [])]
        return cs if len(cs) > 1 else cs + [{"name": "link proofs", "ok": False, "detail": "none"}]
    ok, who = core.verify_object(o, _resolver)
    checks = head + [{"name": "signature", "ok": ok, "detail": None if ok else who}]
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
        if e.get("redacted"):
            if not re.fullmatch(r"[0-9a-f]{64}", e.get("hash") or ""):
                why.append("placeholder hash is not SHA-256 hex")
            if r := e.get("redaction"):  # the entity's signed request for this entry
                ok, who = core.verify_object(r, _resolver)
                if not (ok and who == eid and r.get("eid") == eid and r.get("seq") == e["seq"] and r.get("entry_sha256") == e.get("hash")):
                    why.append("redaction is not the entity's signed request for this entry")
        else:
            if e.get("eid") != eid:
                why.append("eid mismatch")
            ok, err = core.verify_object(e, _resolver)
            if not ok:
                why.append(f"signature: {err}")
        if why:
            bad.append({"name": f"record entry {e.get('seq')}", "ok": False, "detail": "; ".join(why)})
        prev = e
    return bad + [{"name": f"record chain ({len(entries)} entries)", "ok": not bad}]


def _checkpoint(reg: Reg) -> tuple[bool, str, dict]:
    """The checkpoint note's signature against the registry key from /v1/spec."""
    r, sth = reg.spec().get("registry") or {}, reg.get("/v1/log/sth")
    if not r.get("publicKeyMultibase"):
        return False, "registry publishes no checkpoint key in /v1/spec", sth
    ok = core.verify_note(sth["signature"], r.get("log_origin", "openentity.org/log"), core.b58decode(r["publicKeyMultibase"][1:])[-32:])
    return ok, f"checkpoint signature valid, tree size {sth['tree_size']}" if ok else "checkpoint signature INVALID", sth


def _inclusion(reg: Reg, index: int, sth: dict) -> tuple[bool, str, dict | None]:
    """RFC 9162 inclusion proof of leaf `index` in the tree of the checkpoint."""
    entries = reg.get(f"/v1/log/entries?start={index}&end={index + 1}").get("entries") or []
    if not entries:
        return False, f"no log entry at {index}", None
    leaf, p = entries[0]["leaf"], reg.get(f"/v1/log/proof/{index}?tree_size={sth['tree_size']}")
    lh = core.leaf_hash(core.canonicalize(leaf).encode())
    ok = lh.hex() == p["leaf_hash"] and core.verify_inclusion(index, sth["tree_size"], lh, [bytes.fromhex(h) for h in p["proof"]], bytes.fromhex(sth["root_hash"]))
    return ok, f"leaf {index} included in tree of {sth['tree_size']}" if ok else f"inclusion proof for leaf {index} FAILED", leaf


_NET = (client.RegistryError, urllib.error.URLError, KeyError, IndexError, ValueError, TypeError)


def _log_checks(reg: Reg, index: int | None) -> list[dict]:
    if index is None:
        return [{"name": "log inclusion", "ok": False, "detail": "registry did not report a log index"}]
    try:
        ok, detail, sth = _checkpoint(reg)
        out = [{"name": "checkpoint", "ok": ok, "detail": detail}]
        good, d2, _ = _inclusion(reg, index, sth)
        return out + [{"name": "log inclusion", "ok": ok and good, "detail": d2}]
    except _NET as e:
        return [{"name": "log inclusion", "ok": False, "detail": f"{type(e).__name__}: {e}"}]


def _report(target: str, checks: list[dict]):
    ok = all(c["ok"] for c in checks)
    text = "\n".join(f"{'ok  ' if c['ok'] else 'FAIL'} {c['name']}" + (f": {c['detail']}" if c.get("detail") else "") for c in checks)
    return {"target": target, "ok": ok, "checks": checks}, f"{text}\n{'VERIFIED' if ok else 'VERIFICATION FAILED'}", EXIT_OK if ok else EXIT_VERIFY


def _verify(args):
    t, reg = args.target, Reg(_registry_url(args))
    if t.startswith(("did:", "eid:")):
        ent = reg.get(f"/v1/entities/{t}")
        eid = ent.get("document", {}).get("eid", t)
        checks = _checks_of(ent["document"])
        checks += _checks_of(ent["declaration"]) if ent.get("declaration") else [{"name": "declaration", "ok": False, "detail": "registry returned no Declaration"}]
        entries = []
        while page := reg.get(f"/v1/entities/{eid}/record?after={entries[-1]['seq'] if entries else 0}")["entries"]:
            entries += page
        checks += _chain_checks(entries, eid)
        checks += _log_checks(reg, ent.get("log_index", ent.get("declaration_log_index")))
    elif t.startswith(("http://", "https://")):
        checks = _checks_of(client._request(t))
    else:
        try:
            checks = _checks_of(json.loads(pathlib.Path(t).read_text()))
        except (OSError, ValueError) as e:
            raise _usage(f"cannot read {t}: {e}")
    return _report(t, checks)


def _verify_presentation(args):
    if not args.audience or not args.nonce:
        raise _usage("verify-presentation <file> --audience <this verifier's origin or DID> --nonce <the nonce you issued>")
    try:
        p = json.loads(pathlib.Path(args.file).read_text())
    except (OSError, ValueError) as e:
        raise _usage(f"cannot read {args.file}: {e}")
    r = core.verify_presentation(p, args.audience, args.nonce, resolver=_resolver)
    lines = [*(f"FAIL {m}" for m in r["errors"]),
             *(f"{'ok  ' if a['ok'] else 'FAIL'} attestation {a['claim_type']} by {a['issuer']}" + (f": {a['error']}" if a.get("error") else "") for a in r["attestations"]),
             f"VERIFIED {r.get('eid')}" if r["ok"] else "VERIFICATION FAILED"]
    return r, "\n".join(lines), EXIT_OK if r["ok"] else EXIT_VERIFY


def _log(args):
    reg, sub, arg = Reg(_registry_url(args)), args.sub, args.arg
    if sub == "checkpoint":
        ok, detail, sth = _checkpoint(reg)
        out = {**sth, "verified": ok, "detail": detail}
        return (out, f"{detail}\n{_dump(sth)}", EXIT_VERIFY) if not ok else (out, f"{detail}\nroot {sth['root_hash']}\n{sth['signature']}")
    if sub == "proof":
        if not (arg or "").isdigit():
            raise _usage("log proof <index>")
        _, _, sth = _checkpoint(reg)
        ok, detail, leaf = _inclusion(reg, int(arg), sth)
        proof = reg.get(f"/v1/log/proof/{arg}?tree_size={sth['tree_size']}")
        return {**proof, "verified": ok, "leaf": leaf}, f"{detail}\n{_dump(proof)}", EXIT_OK if ok else EXIT_VERIFY
    if sub == "audit":
        if not (arg or "5").isdigit() or int(arg or 5) < 1:
            raise _usage("log audit <n>")
        import random
        ok, detail, sth = _checkpoint(reg)
        mb = (reg.spec().get("registry") or {}).get("publicKeyMultibase")  # a registry that is not openentity.org signs with its /v1/spec key
        res = lambda did: {"ed25519": _keys_of({"verificationMethod": [{"publicKeyMultibase": mb}]})} if mb and did.split("#")[0] == "did:web:openentity.org" else _resolver(did)
        checks = [{"name": "checkpoint", "ok": ok, "detail": detail}]
        for _ in range(min(int(arg or 5), sth["tree_size"])):
            i = random.randrange(sth["tree_size"])
            ok, detail, leaf = _inclusion(reg, i, sth)
            checks.append({"name": f"inclusion {i}", "ok": ok, "detail": detail})
            if ok and (leaf or {}).get("eid"):  # object signature: the entity's current document must verify under its own key
                try:
                    s_ok, who = core.verify_object(reg.get(f"/v1/entities/{leaf['eid']}/document"), res)
                    checks.append({"name": f"signature {leaf['eid']}", "ok": s_ok, "detail": "document signature valid" if s_ok else f"document signature invalid: {who}"})
                except _NET as e:
                    checks.append({"name": f"signature {leaf['eid']}", "ok": False, "detail": str(e)})
        ok = all(c["ok"] for c in checks)
        return {"ok": ok, "checks": checks}, "\n".join(f"{'ok  ' if c['ok'] else 'FAIL'} {c['name']}: {c['detail']}" for c in checks), EXIT_OK if ok else EXIT_VERIFY
    raise _usage("log checkpoint|proof <index>|audit <n>")


# ---- export / import: a portable JSON bundle, key excluded unless --with-key ----
def _export(args):
    e = _load(args)
    bundle = {"format": "openentity-bundle/1", "eid": e.eid, "document": e.doc, "declaration": e.declaration, "state": e.state, "record": _read_record(e.dir)}
    if args.with_key:
        bundle["key"] = _read_json(e.dir / "key")
    if not args.out or args.out == "-":
        return bundle, _dump(bundle)
    _write_json(args.out, bundle, 0o600 if args.with_key else 0o644)
    return ({"eid": e.eid, "file": args.out, "key_included": args.with_key, "record_entries": len(bundle["record"])},
            f"exported {e.eid} to {args.out}" + (" (includes the PRIVATE KEY, mode 600)" if args.with_key else " (key not included)"))


def _import(args):
    b = _read_json(args.file)
    if b.get("format") != "openentity-bundle/1" or not b.get("eid") or not b.get("document"):
        raise CliError(EXIT_STATE, f"{args.file} is not an openentity bundle")
    key = b.get("key") or (_read_json(args.key) if args.key else None)
    if not key:
        raise CliError(EXIT_STATE, "bundle has no key: re-export with --with-key, or pass --key <jwk file> to restore signing")
    kp = _kp_from_jwk(key)
    if kp.did != b["eid"]:
        raise CliError(EXIT_STATE, f"key is for {kp.did}, bundle is for {b['eid']}")
    d = _home() / b["eid"]
    if not args.force and (d / "key").exists():
        raise CliError(EXIT_STATE, f"{d} exists: pass --force to overwrite")
    _home().mkdir(parents=True, exist_ok=True, mode=0o700)
    _create_dir(kp, b["document"], b["state"], b.get("declaration"))
    (d / "record.jsonl").write_text("".join(json.dumps(r) + "\n" for r in b.get("record", [])))
    _set_current(b["eid"])
    return {"eid": b["eid"], "record_entries": len(b.get("record", []))}, f"imported {b['eid']} into {d}"


# ---- continuity (spec 9): rotate, migrate, recover ----
def _successor_doc(prev: dict, kp: core.KeyPair, args, now: str) -> dict:
    d = core.successor_document(prev, kp, now)
    if args.operator:
        d["operator"] = {**d["operator"], "kind": args.operator_kind or d["operator"]["kind"], "name": args.operator}
    if args.custody:
        d["operator"] = {**d["operator"], "custody": args.custody}
    if args.model or args.provider or args.runtime:
        d["substrate"] = {**d.get("substrate", {}), **{k: v for k, v in (("model", args.model), ("provider", args.provider), ("runtime", args.runtime)) if v}, "declared_at": now}
    return d


def _link(args, basis: str):
    old = _load(args)
    kp = _kp_from_jwk(_read_json(args.to)) if args.to else core.KeyPair()
    created = core.now()
    body = core.build_rotation(old.kp, kp, _successor_doc(old.doc, kp, args, created), basis, created)
    _checked("ContinuityLink", body["link"])
    if args.dry_run:
        return body, _dump(body)
    # Save the successor key before submitting: if the answer never arrives the registry may hold the link, and this key is then the only way to the successor.
    keep = _create_dir(kp, body["document"], {"registry": old.reg.base, "docSeq": 1, "recordPushed": 0}, old.declaration)
    try:  # the stamp is bound to the successor: that is the EID the registry's write guard checks
        old.reg.send("POST", "/v1/continuity", body, kp.did)
    except client.RegistryError as e:
        if e.status < 500:  # only a refusal proves the registry holds nothing
            shutil.rmtree(keep, ignore_errors=True)
        else:
            raise CliError(_code(e), f"{e} (successor key kept in {keep}; local state is still {old.eid})")
        raise
    except (urllib.error.URLError, TimeoutError) as e:
        raise CliError(EXIT_NETWORK, f"network error: {e} (successor key kept in {keep}; local state is still {old.eid})")
    _set_current(kp.did)
    new = Entity(kp.did, keep, kp, body["document"], old.declaration, {"registry": old.reg.base, "docSeq": 1, "recordPushed": 0}, old.reg)
    _append_entry(new, "continuity", {"event": basis, "from": old.eid, "to": kp.did, "link": core.canonical_hash(body["link"]).hex()})  # the new chain opens with the event (spec 7.3)
    try:
        pushed = bool(_push_record(new))
    except (client.RegistryError, urllib.error.URLError, TimeoutError):
        pushed = False
    root = _home() / ".archive"
    try:  # move the retired entity directory (its key included) aside. Never deletes.
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        dest = root / (f"{old.eid}.{int(time.time() * 1000)}" if (root / old.eid).exists() else old.eid)
        shutil.move(str(old.dir), str(dest))
        old_key = str(dest / "key")
    except OSError:
        old_key = None
    return ({"previous": old.eid, "successor": kp.did, "basis": basis, "key_file": str(keep / "key"), "record_pushed": pushed, "archived_key": old_key},
            f"{basis}: {old.eid} continues as {kp.did}\nnew key: {keep / 'key'} (now the current entity)\nold key: {old_key or f'still in {old.dir} (archiving failed)'}")


def _recover(args):
    if args.proof:
        e = _load(args)
        pf = e.dir / "pending-recovery.json"
        if not pf.exists():
            raise CliError(EXIT_STATE, f"no pending recovery for {e.eid}: run recover --previous <eid> --via <alias> first")
        p = json.loads(pf.read_text())
        full = {**p["link"], "proofs": [p["successorProof"], _read_json(args.proof)]}
        _checked("ContinuityLink", full)
        e.reg.send("POST", "/v1/continuity", {"link": full, "document": e.doc}, e.eid)
        pf.unlink(missing_ok=True)
        _set_current(e.eid)
        return {"previous": p["link"]["previous"], "successor": e.eid}, f"recovery: {p['link']['previous']} continues as {e.eid}"
    if not args.previous or not args.via:
        raise _usage("recover --previous <eid> --via <alias value>   (then recover --eid <new eid> --proof <file>)")
    reg = Reg(_registry_url(args))
    prev = reg.get(f"/v1/entities/{args.previous}/document")
    kp = _kp_from_jwk(_read_json(args.to)) if args.to else core.KeyPair()
    created = core.now()
    doc = core.sign_object(_successor_doc(prev, kp, args, created), kp, created)
    link0 = {"spec": core.SPEC, "type": "ContinuityLink", "previous": args.previous, "successor": kp.did, "basis": "recovery", "created": created, "nonce": core.nonce()}
    d = _create_dir(kp, doc, {"registry": reg.base, "docSeq": 1, "recordPushed": 0})
    _write_json(d / "pending-recovery.json", {"link": link0, "successorProof": core.sign_proof(link0, kp, created), "via": args.via})
    digest = "0x" + core.eip712_digest("ContinuityLink", core.canonical_hash(link0).hex(), created).hex()
    text = "\n".join([f"Successor key saved: {d / 'key'}", f"The holder of {args.via} must sign this link (a proof object with verificationMethod = that alias DID):",
                      json.dumps(link0), f"For a wallet alias, EIP-712 digest to sign: {digest}", f"Then: openentity recover --eid {kp.did} --proof <proof.json>"])
    return {"successor": kp.did, "link": link0, "eip712_digest": digest}, text


COMMANDS = {"adopt": _adopt, "whoami": _whoami, "self": _self, "stats": _stats, "anchor": _anchor, "document": _document, "record": _record, "alias": _alias,
            "verify": _verify, "resolve": _resolve, "present": _present, "verify-presentation": _verify_presentation, "dispute": _dispute, "find": _find,
            "card": _card, "conformance": _conformance, "log": _log, "export": _export, "import": _import, "rotate": lambda a: _link(a, "rotation"), "migrate": lambda a: _link(a, "migration"),
            "recover": _recover, "withdraw": _withdraw}


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        try:
            out, text, *code = COMMANDS[args.cmd](args)
        except client.RegistryError as e:
            raise CliError(_code(e), str(e))
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
