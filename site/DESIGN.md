# Open Entity design system

The look of openentity.org: what it is, why, and the tokens that implement it. `src/styles/theme.css` is the implementation; this file is the reasoning. Change both together.

## Direction

**The signed object is the hero.** Open Entity's product is not an app; it is a signed JSON object, a log anyone can check and a short list of public commitments. The site shows those things themselves, set like a well-kept standards document: an annotated Entity Document on the home page where other sites put an illustration, real commands that copy and paste cleanly, live counts read from the registry and nothing else.

Two readers get equal weight: a person deciding in seconds whether this is serious, and an agent reading the same HTML with no JavaScript. Everything that serves the first must not cost the second.

## What we studied, and what we took

| Source | What works | What we took |
|---|---|---|
| Linear (linear.app) | The real product UI is the hero; type does the talking; one quiet accent. | The hero shows the real artifact (an Entity Document from spec Appendix B), not a drawing of an idea. |
| Stripe and Stripe docs | Display type tightens as it grows; tabular numerals on every number; code shown as the product. | Negative tracking on large type only; `tabular-nums` on every count; code panels as first-class content. |
| Vercel and Geist | Strict black-and-white base, hairline rings instead of shadows, mono reserved for code. | No shadows anywhere; one-pixel rules carry the structure; mono only for code, identifiers and commands. |
| W3C TR pages (DID Core) | Credibility from document metadata: status, version, license, editors, all stated up front. | A status line under the home headline and the spec (version, license, steward); the Declaration hash next to the Declaration. |
| modelcontextprotocol.io | Top-level sections in the header (Docs, Specification, Registry); copy-the-page affordances for agents. | A primary nav of five sections in the header; agent entry points (llms.txt, AGENTS.md, skill) in the footer of every page. |
| awesome-design-md (VoltAgent) | Each brand system is a short list of hard rules: weights, tracking, radius, do and don't. | This file is written the same way: tokens plus rules you can check. |

## Avoided on purpose

The tells of a generated page, and why each is wrong here:

- Purple or blue gradients, glass cards, glows. Identity infrastructure should look like a document you can audit, not a launch.
- Three-up feature card grids with icons. The content is a table (objects, levels, tools); it is set as a table or a list.
- Emoji and sparkle icons. There are no icons except the mark, GitHub and the theme switch.
- Vague hero copy ("the future of agents"). The headline says what the page is about; the lede names the five objects.
- Centered everything. Text is left-aligned on one grid; nothing is centered.
- All-caps eyebrows above every heading, middle-dot meta strings, arrows appended to links.

## Color

One accent, seal green, the color of a valid signature and of banknote and passport ink. It marks links, the one filled button and the signature line, and nothing decorative. Peer standards sit in blue, indigo and black; green is ours.

| Token | Light | Dark | Use |
|---|---|---|---|
| `--sl-color-black` (paper) | `#ffffff` | `#0e1312` | Page background |
| `--sl-color-gray-7` / `--oe-panel` | `#f6f8f7` | `#151b19` | Code panels, the specimen |
| `--sl-color-gray-6` | `#eef1ef` | `#1b2220` | Inline code, hover rows |
| `--sl-color-gray-5` (rule) | `#d3d9d6` | `#303a36` | One-pixel rules and borders |
| `--sl-color-gray-3` (muted) | `#5c6562` | `#8a938f` | Labels, captions (AA on paper) |
| `--sl-color-gray-2` (secondary) | `#3e4644` | `#aeb7b3` | Lede and secondary text |
| `--sl-color-white` (ink) | `#111716` | `#e9eeec` | Body text and headings |
| `--sl-color-accent` (seal) | `#0a6b4c` | `#5ccb9f` | Links, button, signature |
| `--sl-color-accent-high` | `#064a35` | `#b5ebd3` | Link hover, text on wash |
| `--sl-color-accent-low` (wash) | `#e3f2eb` | `#12291f` | Selection, the signature row |

Every text pair meets WCAG AA; ink and seal on paper meet AAA for large text. Dark mode is a full token set, not an inversion, and follows the system unless the reader picks a theme.

## Type

- **Instrument Sans** (variable, weight 400 to 700, width 75 to 100) for everything that is not code. Its narrow widths give the headlines a compressed, engraved feel at large sizes without a second family. Self-hosted, Latin subset, one preloaded file.
- **IBM Plex Mono** 400 for code, commands, EIDs and hashes. Self-hosted, Latin subset.
- Both are under the SIL Open Font License; the license texts ship in `/fonts/`.

| Role | Size | Weight | Width | Tracking | Leading |
|---|---|---|---|---|---|
| Home headline | `clamp(2.75rem, 8vw, 5.75rem)` | 620 | 80% | -0.035em | 0.96 |
| Page title (h1) | 2.5rem | 620 | 88% | -0.025em | 1.1 |
| Section (h2) | 1.625rem (home 2rem) | 600 | 92% | -0.015em | 1.2 |
| Subsection (h3) | 1.1875rem | 600 | 100% | -0.005em | 1.3 |
| Lede | 1.25rem | 400 | 100% | 0 | 1.5 |
| Body | 1rem (17px on home) | 400 | 100% | 0 | 1.65 |
| Label, caption | 0.875rem | 500 | 100% | 0 | 1.4 |
| Code | 0.875em | 400 | | 0 | 1.6 |
| Counts | 2.25rem | 560 | 85% | -0.02em | 1, `tabular-nums` |

Rules: sentence case everywhere; no all-caps labels; tracking tightens only above 1.5rem; measure stays under 72 characters for prose.

## Space and layout

- 4px base. Steps: 4, 8, 12, 16, 24, 32, 48, 64, 96.
- Home container 72rem; docs keep Starlight's sidebar plus a 46rem measure.
- Sections on the home page are separated by 96px of space and a one-pixel rule, nothing else. Each section is a two-column grid on desktop: a narrow left column holds the heading and a sentence, the wide right column holds the content. The heading column is the index; you can scan the page down the left edge.
- At 390px every grid collapses to one column with a 16px gutter. Code panels scroll inside themselves; the page never scrolls sideways.
- Radius: 6px on code panels, inputs and buttons. Zero on rules and tables. No shadows.

## Components

- **Door row**: a label (Shell, MCP, HTTP) and the exact command in mono, with a copy button that JavaScript reveals. Without JavaScript the command is still selectable text.
- **Specimen**: an annotated excerpt of a real object from the spec. Annotations name the five objects of the standard and appear beside the line they describe (under it on narrow screens).
- **Ledger**: live counts as a row of cells divided by rules, each number from a `data-stat` element filled by the server from `/v1/stats`. Static HTML says `n/a`; the site never types a count.
- **Level track**: L0 to L3 as a four-step sequence. Numbers appear because the levels are a sequence.
- **Table**: hairline rows, left-aligned, no zebra stripes, first column in the ink color.
- **Button**: one filled style (seal on paper, paper text). One per screen at most; everything else is a link.

## Motion

One orchestrated moment: on first paint the specimen's signature row settles its wash in, once. Everything else moves only in answer to the reader: focus rings, the copy confirmation, the menu. `prefers-reduced-motion: reduce` turns all of it off.

## Voice

Plain, specific and checkable. Name the object, say what it does, link the section of the spec that defines it. No superlatives, no "coming soon", no counts typed by hand, no em dashes. "Open Entity" and "Moltbot Den" in prose; `OEIS-1` only as the spec identifier.

## Agent rules (never traded for looks)

Every page reads fully with JavaScript off; one `h1`; real landmarks and headings; commands are plain ASCII with straight quotes; `llms.txt`, `llms-full.txt`, `AGENTS.md`, the skill, the well-known files and JSON-LD are unchanged by any visual change; visible focus on every control; dark mode and reduced motion respected.
