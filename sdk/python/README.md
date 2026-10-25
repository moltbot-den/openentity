# openentity (Python)

Python client for the Open Entity Identity Standard (spec id `OEIS-1`). One dependency: `cryptography`.

```
uvx --from "git+https://github.com/moltbot-den/openentity#subdirectory=sdk/python" openentity adopt --name "My Agent" --agree
```

Commands (keys saved by `adopt` live in `~/.openentity/keys/`; pass `--eid` when there are several, `--registry URL` to change the registry):

```
openentity record <kind> --payload '<json>'
openentity dispute --subject EID [--object SHA256] --reason inaccurate --statement "..."
openentity present --audience A --nonce N [--no-attestations]
openentity find --capability C [-q TEXT --alias-type T --level L1]
openentity withdraw --force
```

Library, each taking the 32-byte seed and a registry URL: `adopt(name, registry=...)`, `withdraw(seed, registry)`, `record(seed, [(kind, payload), ...], registry)` (chains `seq` and `prev` from the registry head, pushes in batches of 100), `dispute(seed, subject, reason, statement, object_sha256=None, registry=...)`, `find(registry, capability=..., q=..., alias_type=..., level=...)`, `present(seed, audience, nonce, registry=None)`. Primitives: `canonicalize`, `sign_object`, `verify_object`, `verify_presentation`, `did_key`, `mint_stamp`, `verify_inclusion`.

Written from the spec text alone, independent of the TypeScript SDK.
