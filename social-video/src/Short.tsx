import { loadFont } from "@remotion/fonts";
import React from "react";
import { AbsoluteFill, Audio, Img, interpolate, spring, staticFile, useCurrentFrame, useVideoConfig } from "remotion";
import { THEMES } from "./theme.ts";
import { type ShortProps } from "./types.ts";

const SANS = "Instrument Sans", MONO = "IBM Plex Mono";
loadFont({ family: SANS, url: staticFile("fonts/instrument-sans-latin.woff2"), weight: "400 700" });
loadFont({ family: MONO, url: staticFile("fonts/plex-mono-400-latin.woff2"), weight: "400" });

/** TikTok, Reels and Shorts cover the bottom 300 px and the right edge: text stays inside 90..990 wide and above y 1560. */
const Headline: React.FC<{ text: string; color: string; from: number }> = ({ text, color, from }) => {
  const frame = useCurrentFrame(), { fps } = useVideoConfig();
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: "0 28px", fontFamily: SANS, fontWeight: 700, fontSize: 124, lineHeight: 1.04, letterSpacing: -3, color }}>
      {text.split(" ").map((w, i) => {
        const p = spring({ frame: frame - from - i * 4, fps, config: { damping: 16, stiffness: 160 } });
        return <span key={i} style={{ opacity: p, transform: `translateY(${(1 - p) * 60}px)`, display: "inline-block" }}>{w}</span>;
      })}
    </div>
  );
};

export const Short: React.FC<ShortProps> = ({ variant, beats, words, audio, durationSec }) => {
  const frame = useCurrentFrame(), { fps } = useVideoConfig();
  const t = frame / fps, th = THEMES[variant];
  const bi = Math.max(0, beats.findIndex((b) => t >= b.from && t < b.to));
  const beat = beats[t >= (beats.at(-1)?.to ?? 0) ? beats.length - 1 : bi];
  const accent = th.beat[bi % th.beat.length]!;
  const beatFrom = Math.round((beat?.from ?? 0) * fps);
  // Captions: pages of three words, the spoken one highlighted.
  const wi = words.findLastIndex((w) => t >= w.from);
  const page = wi < 0 ? 0 : Math.floor(wi / 3);
  const shown = words.slice(page * 3, page * 3 + 3);
  const drift = (frame * 0.6) % 120;
  return (
    <AbsoluteFill style={{ background: th.bg, color: th.text, fontFamily: SANS }}>
      {audio ? <Audio src={audio} /> : null}
      {variant === 0 && <AbsoluteFill style={{ backgroundImage: `linear-gradient(${th.hair} 1px, transparent 1px), linear-gradient(90deg, ${th.hair} 1px, transparent 1px)`, backgroundSize: "120px 120px", backgroundPosition: `${drift}px ${drift}px`, opacity: 0.55 }} />}
      {variant === 1 && <div style={{ position: "absolute", right: -380, top: -300, width: 1100, height: 1100, borderRadius: "50%", background: th.low, transform: `scale(${1 + Math.sin(frame / 40) * 0.04})` }} />}
      {variant === 2 && [0, 1, 2, 3].map((i) => (
        <div key={i} style={{ position: "absolute", left: 540 - (260 + i * 170), top: 1000 - (260 + i * 170), width: (260 + i * 170) * 2, height: (260 + i * 170) * 2, borderRadius: "50%", border: `3px solid ${accent}`, opacity: 0.28 - i * 0.05, transform: `scale(${1 + Math.sin(frame / 30 + i) * 0.03})` }} />
      ))}
      <div style={{ position: "absolute", left: 90, right: 90, top: 110, display: "flex", alignItems: "center", gap: 28 }}>
        <Img src={staticFile("logo.png")} style={{ width: 96, height: 96, borderRadius: 22 }} />
        <div style={{ fontSize: 52, fontWeight: 600, letterSpacing: -1 }}>Open Entity</div>
      </div>
      <div style={{ position: "absolute", left: 90, right: 90, top: 380, height: 780, display: "flex", flexDirection: "column", justifyContent: "center", gap: 48 }}>
        <div style={{ width: 120, height: 14, borderRadius: 7, background: accent }} />
        {beat ? <Headline key={bi} text={beat.show} color={th.text} from={beatFrom} /> : null}
        {beat?.stat ? (
          <div style={{ fontFamily: MONO, color: accent, display: "flex", alignItems: "baseline", gap: 28 }}>
            <span style={{ fontSize: 230, lineHeight: 1 }}>{beat.stat.value}</span>
            <span style={{ fontSize: 56, color: th.muted }}>{beat.stat.label}</span>
          </div>
        ) : null}
      </div>
      <div style={{ position: "absolute", left: 90, right: 90, top: 1240, minHeight: 230, padding: "40px 48px", borderRadius: 36, background: th.panel, border: `2px solid ${th.hair}`, display: "flex", flexWrap: "wrap", alignContent: "center", gap: "8px 24px", fontSize: 84, fontWeight: 700, letterSpacing: -1.5 }}>
        {shown.map((w, i) => <span key={page * 3 + i} style={{ color: page * 3 + i === wi ? accent : th.text }}>{w.text}</span>)}
      </div>
      <div style={{ position: "absolute", left: 90, right: 90, top: 1560, height: 10, borderRadius: 5, background: th.hair }}>
        <div style={{ width: `${interpolate(t, [0, durationSec], [0, 100], { extrapolateRight: "clamp" })}%`, height: "100%", borderRadius: 5, background: accent }} />
      </div>
      <div style={{ position: "absolute", left: 90, top: 1600, fontFamily: MONO, fontSize: 44, color: th.muted }}>openentity.org</div>
    </AbsoluteFill>
  );
};
