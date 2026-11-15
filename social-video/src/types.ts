/** Input props of the Short composition. The registry builds them (registry/src/video.ts videoProps); times are seconds. */
export type ShortProps = {
  variant: 0 | 1 | 2;
  /** One headline per script beat; `stat` shows a live number from /v1/stats big on screen. */
  beats: { show: string; from: number; to: number; stat?: { value: string; label: string } }[];
  /** Spoken words with their time in the voiceover, for the burned-in captions. */
  words: { text: string; from: number; to: number }[];
  audio: string;
  durationSec: number;
};
export const FPS = 30;
export const defaultProps: ShortProps = {
  variant: 0,
  beats: [
    { show: "One identity for every agent", from: 0, to: 4 },
    { show: "Entities in the registry", from: 4, to: 8, stat: { value: "27", label: "entities" } },
  ],
  words: "One identity for every agent. Check the registry yourself.".split(" ").map((text, i) => ({ text, from: i * 0.5, to: i * 0.5 + 0.5 })),
  audio: "",
  durationSec: 20,
};
