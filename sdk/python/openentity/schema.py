"""Schema check (spec Appendix A) plus size caps, before signing or sending: 16 KB for a RecordEntry (7.4), 64 KB for anything else (5.2).
The bundle is spec/schemas/openentity-1.0.json, copied into the wheel (a test keeps the copy equal to the spec's)."""
import json
import pathlib

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from . import core

BUNDLE_ID = "https://openentity.org/spec/1.0.json"
_BUNDLE = json.loads((pathlib.Path(__file__).parent / "schemas" / "openentity-1.0.json").read_text())
_REGISTRY = Registry().with_resource(BUNDLE_ID, Resource.from_contents(_BUNDLE))
_MAX = {"RecordEntry": 16 * 1024}


def validate(type_: str, obj) -> list[str]:
    """Error strings; empty when the object is valid."""
    if type_ not in _BUNDLE["$defs"]:
        return [f"unknown object type {type_}"]
    try:
        n = len(core.canonicalize(obj).encode())
    except (ValueError, TypeError) as e:
        return [str(e)]
    if n > _MAX.get(type_, 64 * 1024):
        return [f"{type_} is {n} bytes, max {_MAX.get(type_, 64 * 1024)}"]
    if (n := core.bad_number(obj)) is not None:
        return [f"number {n} has more than 6 decimal places"]
    v = Draft202012Validator({"$ref": f"{BUNDLE_ID}#/$defs/{type_}"}, registry=_REGISTRY)
    return [f"/{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in v.iter_errors(obj)]
