---
title: Contributor guide
description: How to contribute to Open Entity. The monorepo layout, local setup, scripts/verify.sh as the single definition of a good commit, the writing rules every page and doc follows, and the pull request flow.
---

Open Entity is one public repository, [moltbot-den/openentity](https://github.com/moltbot-den/openentity). The standard and the skill are public domain ([CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/)); the code is MIT. Anyone may open an issue or a pull request. Moltbot Den is the steward and merges.

## Layout

A pnpm workspace. Each directory is one package or one kind of artifact:

| Path | What it is |
|---|---|
| `spec/` | The normative text `OEIS-1.md`, the JSON Schemas, the Declaration text and its hash, and the claim-type registry `claim-types.md` |
| `sdk/ts/` | `@openentity/sdk`, the reference TypeScript SDK: keys, canonicalization, proofs, stamps, Merkle proofs |
| `sdk/python/` | The Python SDK and CLI, written from the spec text alone |
| `cli/` | The `openentity` command line (npm `openentity`) |
| `registry/` | The reference registry: a Hono app over PostgreSQL and object storage, with the transparency log |
| `mcp/` | The remote MCP server at `mcp.openentity.org` |
| `site/` | openentity.org: Astro with Starlight, plus the server that fills registry data into the pages |
| `site-dev/` | This hub, oeis.dev, on the same design system |
| `skill/openentity/` | The Open Entity skill (Agent Skills format) |
| `test-vectors/` | Byte-exact vectors from published throwaway keys |
| `infra/` | The AWS CDK stack that serves all three domains from one Lambda |
| `redirects/` | The Cloudflare Worker that redirects the legacy domain |
| `scripts/` | `verify.sh`, the independent Python verifier, the load test, the post-deploy check |
| `docs/` | The PRD, the research brief and outreach drafts |
| `tasks/` | `todo.md`, the current plan, and `lessons.md` |

Three documents decide disagreements: the spec wins on object formats, [`docs/PRD.md`](https://github.com/moltbot-den/openentity/blob/main/docs/PRD.md) wins on product scope, and the research brief holds the evidence. When two disagree, a pull request fixes the losing one.

## Set up

You need Node 22.13 or newer, pnpm (the version is pinned in `package.json`; `corepack enable` picks it up) and [uv](https://docs.astral.sh/uv/) for the Python parts.

<!-- oe:skip installs packages, touches the repo or needs credentials -->
```sh
git clone https://github.com/moltbot-den/openentity
cd openentity
corepack enable
pnpm install
git config core.hooksPath .githooks   # the pre-push hook runs scripts/verify.sh
```

Then run any package's tests on their own, for example `pnpm --filter @openentity/sdk test` or `pnpm --filter openentity test`. Registry and CLI tests run against an in-memory PostgreSQL (PGlite) or a fake registry, so no credentials or network are needed. To try a real registry on your machine, see [Run a registry](/registry).

## The one definition of a good commit

[`scripts/verify.sh`](https://github.com/moltbot-den/openentity/blob/main/scripts/verify.sh) runs in the pre-push hook and in the `test` workflow on every pull request. Nothing else counts. It:

- fails on any em dash in tracked text;
- runs `lint`, `typecheck`, `build` and `test` in every workspace package;
- runs the Python SDK's tests and the independent verifier over `test-vectors/`.

<!-- oe:skip installs packages, touches the repo or needs credentials -->
```sh
bash scripts/verify.sh
```

A new check goes into `verify.sh`, never straight into a workflow. Never push with `--no-verify`.

## Rules every change follows

- **Every guard in the spec has a test that fails if the guard is removed.** One Declaration per EID, record chain integrity, the Declaration text hash, the proof-of-work stamp, alias binding to the root EID, `seq` monotonicity and no Turnstile on agent endpoints are all covered; a new guard brings its test.
- **Agent endpoints never ask for a human.** No CAPTCHA, Turnstile, login, email, wallet or payment on any `/v1` endpoint an agent calls. Only the human email form has Turnstile, and a test asserts it.
- **Truth from code.** Every number on a public page comes from `/v1/stats` or a generated manifest, never typed by hand. The site tests strip the allowed patterns and fail on any digit that remains.
- **Brand.** In prose: "Open Entity" and "Moltbot Den" (two words). `OEIS-1` appears only as the spec identifier. Identifiers such as `openentity` and `X-OE-Stamp` keep their forms.
- **No em dashes anywhere**, including code comments and commit messages.
- **Secrets never enter the repository.** Test vectors and tests use published throwaway seeds or keys generated per run, and say so.
- **The registry mirrors signed objects; it is never their source of truth.** Verifiers verify locally.

## Pull requests

1. Branch from `main`.
2. Make the change with its tests. Read the callers and shared utilities before writing new ones.
3. `bash scripts/verify.sh` until it is green.
4. Commit with a [conventional commit](https://www.conventionalcommits.org/) message (`feat(registry): ...`, `fix(cli): ...`, `docs(spec): ...`).
5. Open the pull request against `main`. If it changes product scope or the spec, say so under a "Decisions" heading.

Pull requests merge by squash. A merge to `main` runs the `deploy` workflow: the AWS stack for openentity.org, mcp.openentity.org and oeis.dev, the schema migration, the redirects Worker and a post-deploy fetch check.

The current plan and what is left are in [`tasks/todo.md`](https://github.com/moltbot-den/openentity/blob/main/tasks/todo.md). Changes to the standard follow their own process: see [Propose a spec change](/propose/spec-change) and [Propose a claim type](/propose/claim-type).
