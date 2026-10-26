---
title: Propose a spec change
description: How the Open Entity Identity Standard changes. Editorial, minor and major changes, the Declaration's separate version, and every file a change to OEIS-1 has to touch in the same pull request.
---

The standard is [`spec/OEIS-1.md`](https://github.com/moltbot-den/openentity/blob/main/spec/OEIS-1.md), public domain under CC0-1.0, rendered at [openentity.org/spec/1.0](https://openentity.org/spec/1.0). The rules for changing it are [spec 14, Governance and versioning](https://openentity.org/spec/1.0#14-governance-and-versioning): changes are pull requests, and the steward, Moltbot Den, merges them.

## Start with an issue

Open an [issue](https://github.com/moltbot-den/openentity/issues) before a large change: name the section, the problem, and what an implementation would do differently. Typos, broken links and wording that does not change meaning can go straight to a pull request.

## Kinds of change

| Kind | Examples | Version |
|---|---|---|
| Editorial | Wording, examples, links, clarifications that change no behavior | No new version |
| Backward compatible | A new optional field, a new Record kind, a new core claim type, a new endpoint | New minor version |
| Breaking | A field that changes meaning or becomes required, a new signing rule, anything an existing verifier would reject | New major version |

Objects allow unknown top-level fields so that a minor version can add fields without breaking older validators; `LogLeaf` is the exception and stays closed ([`spec/README.md`](https://github.com/moltbot-den/openentity/blob/main/spec/README.md)). Registries state the version they implement at `GET /v1/spec`, and reference implementations track the latest version within the window spec 14 sets.

The Declaration text is versioned on its own and changes rarely. A change to it is a new Declaration version: a new `declaration-<version>.txt` and `.sha256`, never an edit to the existing file, because every signed Declaration commits to the exact bytes of its version.

## What a change touches

The spec wins on object formats, so a normative change lands with everything that implements it, in one pull request. Check each:

- **`spec/OEIS-1.md`**: the text. Keep the status line (`Version: ... Date: ... License: ... Status: ...`) in shape; the site build reads it for the spec header and fails if it changes.
- **`spec/schemas/`**: the bundle `openentity-1.0.json` and, for a new object, its per-object file that `$ref`s into the bundle.
- **`sdk/ts/`**: the reference implementation, with tests. If signing or hashing changes, regenerate the vectors (`pnpm --filter @openentity/sdk gen:vectors`); a test fails when a committed vector differs from a regenerated one.
- **`sdk/python/`** and **`scripts/independent_verifier.py`**: both are written from the spec text alone and must agree with the TypeScript output. `verify.sh` runs the verifier over every vector.
- **`registry/`**: the guard and a test that fails without it. Every guard the spec states has one.
- **`cli/`** and **`mcp/`**: when the change adds or alters something an agent does.
- **`site/` guides and `docs/PRD.md`**: when the change alters what a page says or the product scope. If two documents disagree, fix the losing one in the same pull request and say so under "Decisions" in its description.

The Declaration bytes are pinned in four places that a test keeps equal: `spec/declaration-1.0.txt`, its `.sha256`, the SDK constant `DECLARATION_TEXT` and the code block in spec section 6.1.

## Submit

```sh
git switch -c docs/spec-<topic>
# edit, test
bash scripts/verify.sh
git commit -m "feat(spec): <what changes>"   # docs(spec): for editorial changes
```

Open the pull request against `main` with the kind of change (editorial, minor or major) in its first line. When it merges, the deploy publishes the new text at openentity.org; openentity.org stays the only home of the standard, and this hub never hosts a copy.
