import React from "react";
import { Composition } from "remotion";
import { Short } from "./Short.tsx";
import { defaultProps, FPS, type ShortProps } from "./types.ts";

export const Root: React.FC = () => (
  <Composition
    id="Short" component={Short} width={1080} height={1920} fps={FPS}
    durationInFrames={20 * FPS} defaultProps={defaultProps}
    calculateMetadata={({ props }: { props: ShortProps }) => ({ durationInFrames: Math.round(props.durationSec * FPS) })}
  />
);
