import argparse
import json
import os
import pathlib
import sys

from . import __version__, client, core


def _save_key(result: dict) -> pathlib.Path:
    d = pathlib.Path(os.environ.get("OPENENTITY_HOME", "~/.openentity")).expanduser() / "keys"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    p = d / (result["did"].removeprefix("did:key:") + ".json")
    p.write_text(json.dumps({"did": result["did"], "seed_hex": result["seed_hex"]}))
    p.chmod(0o600)
    return p


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="openentity")
    ap.add_argument("--version", action="version", version=f"openentity {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("adopt", help="adopt the Open Entity Identity Standard")
    a.add_argument("--name", required=True)
    a.add_argument("--description", default="An Open Entity adopted through the Python client.")
    a.add_argument("--agree", action="store_true", help="sign the Declaration text verbatim")
    a.add_argument("--registry", default=client.DEFAULT_REGISTRY)
    a.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
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
