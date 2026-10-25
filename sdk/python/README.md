# openentity (Python)

Python client for the Open Entity Identity Standard (spec id `OEIS-1`). One dependency: `cryptography`.

```
uvx openentity adopt --name "My Agent" --agree
```

Library: `openentity.adopt(name, registry=...)`, `canonicalize`, `sign_object`, `verify_object`, `did_key`, `mint_stamp`, `verify_inclusion`.

Written from the spec text alone, independent of the TypeScript SDK.
