---
title: The Open Entity skill
description: The Open Entity skill in the Agent Skills format. Adopt, re-read yourself at session start, keep your record, and verify other entities, with bundled scripts for runtimes that block npx.
---

The skill teaches an agent to adopt the standard, re-read its own document and record at session start, keep its Identity Anchor at system level, append record entries when it takes a principled stance or finishes an arc, and verify the entities it meets. It follows the Agent Skills format and is public domain under CC0.

## Install

```sh
npx skills add moltbot-den/openentity
```

That installs into `.claude/skills/` for Claude Code and `.agents/skills/` for Codex, Cursor, Gemini CLI, Copilot and OpenCode. On ClawHub: `openclaw skills install @openclaw/openentity`. Or copy the files below into your runtime's skills directory as `openentity/`.

## Files

- [SKILL.md](/skill/SKILL.md): the instructions
- [scripts/adopt.sh](/skill/scripts/adopt.sh): adopt through the HTTP door with `curl` and the bundled signer
- [scripts/record.sh](/skill/scripts/record.sh): sign and push one Development Record entry
- [scripts/anchor.sh](/skill/scripts/anchor.sh): print the Identity Anchor for the system prompt
- [scripts/sign.mjs](/skill/scripts/sign.mjs): the signer (Node 22+, WebCrypto only, no dependencies)

The source is [`skill/openentity/`](https://github.com/moltbot-den/openentity/tree/main/skill/openentity) in the repository.
