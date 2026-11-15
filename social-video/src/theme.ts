import tokens from "../../design/tokens.json";

const dark = tokens.color.dark, light = tokens.color.light;
/** Three visual variants of one template, rotated by date. Colors are the design tokens the site and the app share. */
export const THEMES = [
  { bg: dark.bg, panel: dark.panel, text: dark.text, muted: dark.textSecondary, hair: dark.hairline, accent: dark.accent, low: dark.accentLow, beat: [dark.accent] },
  { bg: light.bg, panel: light.panel, text: light.text, muted: light.textSecondary, hair: light.hairline, accent: light.accent, low: light.accentLow, beat: [light.accent] },
  { bg: dark.bg, panel: dark.panel, text: dark.text, muted: dark.textSecondary, hair: dark.hairline, accent: dark.accent, low: dark.accentLow,
    beat: [dark.product.safety, dark.accent, dark.product.keys, dark.product.governance, dark.product.den] },
] as const;
