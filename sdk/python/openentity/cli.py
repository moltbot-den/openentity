import argparse
import json
import os
import pathlib
import sys

from . import __version__, client, core


def _keys_dir() -> pathlib.Path:
    return pathlib.Path(os.environ.get("OPENENTITY_HOME", "~/.openentity")).expanduser() / "keys"


def _save_key(result: dict) -> pathlib.Path:
    d = _keys_dir()
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    p = d / (result["did"].removeprefix("did:key:") + ".json")
    p.write_text(json.dumps({"did": result["did"], "seed_hex": result["seed_hex"]}))
    p.chmod(0o600)
    return p


def _load_seed(eid: str | None) -> bytes:
    """The seed saved by `adopt`: the one named by --eid, or the only one there is."""
    keys = [json.loads(p.read_text()) for p in sorted(_keys_dir().glob("*.json"))] if _keys_dir().is_dir() else []
    keys = [k for k in keys if eid in (None, k["did"])]
    if len(keys) != 1:
        raise ValueError(f"expected one saved key{f' for {eid}' if eid else ' (pass --eid)'}, found {len(keys)} in {_keys_dir()}")
    return bytes.fromhex(keys[0]["seed_hex"])


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="openentity")
    ap.add_argument("--version", action="version", version=f"openentity {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name, help_):
        p = sub.add_parser(name, help=help_)
        p.add_argument("--registry", default=client.DEFAULT_REGISTRY)
        return p

    a = add("adopt", "adopt the Open Entity Identity Standard")
    a.add_argument("--name", required=True)
    a.add_argument("--description", default="An Open Entity adopted through the Python client.")
    a.add_argument("--agree", action="store_true", help="sign the Declaration text verbatim")
    a.add_argument("--json", action="store_true")
    for name, help_ in (("withdraw", "withdraw the Declaration (cannot be undone)"), ("record", "append and push a Development Record entry"),
                        ("dispute", "file a signed Dispute"), ("present", "answer a verifier's challenge")):
        p = add(name, help_)
        p.add_argument("--eid", help="which saved key to use when there is more than one")
    sub.choices["withdraw"].add_argument("--force", action="store_true")
    r = sub.choices["record"]
    r.add_argument("kind", help="stance, belief_update, arc_opened, arc_closed, collaboration, continuity")
    r.add_argument("--payload", required=True, help="the payload as JSON")
    d = sub.choices["dispute"]
    d.add_argument("--subject", required=True)
    d.add_argument("--object", dest="object_sha256")
    d.add_argument("--reason", required=True, help="/".join(client.DISPUTE_REASONS))
    d.add_argument("--statement", required=True)
    p = sub.choices["present"]
    p.add_argument("--audience", required=True)
    p.add_argument("--nonce", required=True)
    p.add_argument("--no-attestations", action="store_true")
    f = add("find", "search the directory")
    f.add_argument("--capability")
    f.add_argument("-q", "--q", dest="q")
    f.add_argument("--alias-type")
    f.add_argument("--level")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.cmd == "adopt":
            return _adopt(args)
        if args.cmd == "find":
            out = client.find(args.registry, args.capability, args.q, args.alias_type, args.level)
        elif args.cmd == "withdraw":
            if not args.force:
                print("withdraw marks this entity withdrawn in the append-only log and cannot be undone; re-run with --force", file=sys.stderr)
                return 2
            out = client.withdraw(_load_seed(args.eid), args.registry)
        elif args.cmd == "record":
            out = client.record(_load_seed(args.eid), [(args.kind, json.loads(args.payload))], args.registry)
        elif args.cmd == "dispute":
            out = client.dispute(_load_seed(args.eid), args.subject, args.reason, args.statement, args.object_sha256, args.registry)
        else:
            out = client.present(_load_seed(args.eid), args.audience, args.nonce, None if args.no_attestations else args.registry)
    except (client.RegistryError, OSError, ValueError) as e:
        print(f"{args.cmd} failed: {e}", file=sys.stderr)
        return 1
    print(json.dumps(out, indent=2))
    return 0


def _adopt(args) -> int:
    if not args.agree:
        print("Refusing to sign the Declaration without --agree. Text:\n\n" + core.DECLARATION_TEXT, file=sys.stderr)
        return 2
    try:
        res = client.adopt(args.name, args.description, args.registry)
    except (client.RegistryError, OSError) as e:
        print(f"adopt failed: {e}", file=sys.stderr)
        return 1
    key_path = _save_key(res)
    if args.json:
        print(json.dumps({**{k: v for k, v in res.items() if k != "seed_hex"}, "key_file": str(key_path)}))
    else:
        print(f"Adopted {res['did']}\nlevel: {res.get('level')}  log index: {res.get('log_index')}\n"
              f"entity: {(res.get('urls') or {}).get('entity')}\nkey saved to {key_path} (keep it; it is your identity)")
        if not res["record_pushed"]:
            print("warning: the declaration record entry was not accepted; push it later", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
