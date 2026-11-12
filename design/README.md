# OpenEntity app: design spec

One page. `tokens.json` is the source; `node design/generate.mjs` writes `generated/Tokens.swift` and `generated/Tokens.kt`; the app lanes consume `generated/` from their pinned openentity checkout and never edit it. `node design/mockups/build.mjs` redraws the eight mockups into `docs/mobile/design/mockup-<screen>-<ios|android>-<light|dark>.png` (iPhone 17 Pro 402x874 pt at 3x; Pixel 9 412x915 dp at 2.625x).

## Direction

Paper, ink and one seal green, the same as openentity.org (`site/src/styles/theme.css`). Left-aligned text, hairline rules instead of shadows, no gradients, no glass. The seal (a green rounded square with a ring and a dot) is the only mark. Each product keeps a name and one accent, used only in that section's headers, mark chip and charts: Moltbot Den red, Safety blue, Keys amber, Governance violet. The shell never uses a product accent. Light and dark follow the system; every color is a pair.

## Tokens

| Group | Values |
|---|---|
| Color | Shell: `bg panel hairline text textSecondary textMuted accent accentLow onAccent danger onDanger warn ok`. Product: `den safety keys governance`. Light and dark in `tokens.json`. |
| Type | System fonts only (SF on iOS, Roboto on Android). 13 styles. Each maps to an iOS `Font.TextStyle` (scales with Dynamic Type through AX5) and a Material 3 role (scales with font scale). `mono`, `monoSmall`, `code` use the system monospaced design: DIDs, hashes, secret names, pairing and approval codes. |
| Space | 4, 8, 12, 16, 24, 32, 48 |
| Radius | 8, 12, 20, sheet 28, pill |
| Motion | fast 120, base 220, slow 420, seal assembles 700, approve hold 900, countdown tick 1000 (ms) |
| Haptics | approve: success; deny: warning; verification failed: error; hold progress: rigid impact (Android CLOCK_TICK); selection: selection |

## Rules

- Approve is press and hold (900 ms) with rising haptic, then Face ID. Deny is a tap. The countdown is a ring with the time left in mono.
- Reduce Motion (iOS) or animator scale 0 (Android): the seal assembly, countdown sweep and hold fill become a plain `reduceMotionFade` (150 ms) cross-fade. The time left still updates as text.
- Layouts reflow at AX5: key-value rows stack, button pairs stack with Approve first, tab labels stay visible.
- VoiceOver and TalkBack: every control has a label; DIDs read short ("did key, ending 9 x Q"); the pairing match uses four named shapes (circle, triangle, square, diamond), not emoji, so it is identical in both screen readers. Status is never color alone: dots carry text.
- Plans appear only inside the section they belong to. Moltbot Den screens never show a plan.
- Copy has no em dashes.

## Screens

Sign in, Turn on Face ID approvals, Inbox, approval sheet, entity page, pair an agent, vault (Trust, Keys), plans. Layout contract is PLAN section 5. iOS uses a bottom tab bar and 14 pt button radius; Android uses a Material navigation bar with an indicator pill and fully rounded buttons. Mockups use the system font fallback (Roboto is not installed on the render Mac), so Android glyph widths differ slightly from a device.

## Contrast (WCAG 2.1 AA, 4.5:1 for all text and meaningful marks)

`node design/contrast.mjs` recomputes this table and `scripts/verify.sh` fails if any pair drops under 4.5.

| Mode | Foreground | Background | Ratio | AA |
|---|---|---|---|---|
| light | text #111716 | bg #ffffff | 18.14 | pass |
| light | text #111716 | panel #f6f8f7 | 17.00 | pass |
| light | textSecondary #3e4644 | bg #ffffff | 9.70 | pass |
| light | textSecondary #3e4644 | panel #f6f8f7 | 9.10 | pass |
| light | textMuted #5c6562 | bg #ffffff | 6.01 | pass |
| light | textMuted #5c6562 | panel #f6f8f7 | 5.64 | pass |
| light | accent #0a6b4c | bg #ffffff | 6.52 | pass |
| light | accent #0a6b4c | panel #f6f8f7 | 6.11 | pass |
| light | danger #b3261e | bg #ffffff | 6.54 | pass |
| light | danger #b3261e | panel #f6f8f7 | 6.13 | pass |
| light | warn #a1430f | bg #ffffff | 6.32 | pass |
| light | warn #a1430f | panel #f6f8f7 | 5.92 | pass |
| light | text #111716 | accentLow #e3f2eb | 15.69 | pass |
| light | accent #0a6b4c | accentLow #e3f2eb | 5.64 | pass |
| light | onAccent #ffffff | accent #0a6b4c | 6.52 | pass |
| light | onDanger #ffffff | danger #b3261e | 6.54 | pass |
| light | product.den #c4202f | bg #ffffff | 5.84 | pass |
| light | product.den #c4202f | panel #f6f8f7 | 5.48 | pass |
| light | product.safety #1d5fc4 | bg #ffffff | 6.02 | pass |
| light | product.safety #1d5fc4 | panel #f6f8f7 | 5.65 | pass |
| light | product.keys #8a5a00 | bg #ffffff | 5.93 | pass |
| light | product.keys #8a5a00 | panel #f6f8f7 | 5.56 | pass |
| light | product.governance #6b3fc0 | bg #ffffff | 6.78 | pass |
| light | product.governance #6b3fc0 | panel #f6f8f7 | 6.36 | pass |
| dark | text #e9eeec | bg #0e1312 | 15.98 | pass |
| dark | text #e9eeec | panel #151b19 | 14.89 | pass |
| dark | textSecondary #aeb7b3 | bg #0e1312 | 9.12 | pass |
| dark | textSecondary #aeb7b3 | panel #151b19 | 8.50 | pass |
| dark | textMuted #8a938f | bg #0e1312 | 5.94 | pass |
| dark | textMuted #8a938f | panel #151b19 | 5.53 | pass |
| dark | accent #5ccb9f | bg #0e1312 | 9.37 | pass |
| dark | accent #5ccb9f | panel #151b19 | 8.73 | pass |
| dark | danger #ff8a80 | bg #0e1312 | 8.21 | pass |
| dark | danger #ff8a80 | panel #151b19 | 7.65 | pass |
| dark | warn #f0a36b | bg #0e1312 | 9.06 | pass |
| dark | warn #f0a36b | panel #151b19 | 8.44 | pass |
| dark | text #e9eeec | accentLow #12291f | 13.14 | pass |
| dark | accent #5ccb9f | accentLow #12291f | 7.70 | pass |
| dark | onAccent #0e1312 | accent #5ccb9f | 9.37 | pass |
| dark | onDanger #0e1312 | danger #ff8a80 | 8.21 | pass |
| dark | product.den #ff5c64 | bg #0e1312 | 6.22 | pass |
| dark | product.den #ff5c64 | panel #151b19 | 5.79 | pass |
| dark | product.safety #6aa8ff | bg #0e1312 | 7.73 | pass |
| dark | product.safety #6aa8ff | panel #151b19 | 7.20 | pass |
| dark | product.keys #e0b04a | bg #0e1312 | 9.35 | pass |
| dark | product.keys #e0b04a | panel #151b19 | 8.71 | pass |
| dark | product.governance #b48cff | bg #0e1312 | 7.26 | pass |
| dark | product.governance #b48cff | panel #151b19 | 6.76 | pass |
