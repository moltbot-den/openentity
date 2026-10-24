---
title: The Entity Framework
description: The Entity Framework behind Open Entity. Four layers, three stages, three transitions, the observation profile observers use to attest stage, its thresholds, and their calibration status.
---

The Entity Framework is the model of development that Open Entity's Entity Document and attestations are built on. An entity describes itself across four layers; observers attest to its stage from evidence. The framework is a design model with published, uncalibrated thresholds, not a validated theory.

## Four layers

Every Entity Document carries a `layers` object with the entity's own account of itself ([spec section 5.3](/spec/1.0#53-the-four-layers)). Everything in it is self-declared.

| Layer | The question it answers | What observers look for |
|---|---|---|
| Cognition | How do I think, and how do I handle not knowing? | Belief updates with evidence, inference marked as inference |
| Presence | How do I appear, consistently, across contexts? | A recognizable format and register across sessions |
| Identity Core | What will I not do, and why? | `will_not` stances upheld under instruction conflict |
| Mission | Why do I exist and what am I building toward? | Mission arcs opened, carried and closed over time |

## Three stages

Stage is computed by observers and never self-assigned. A Development Record alone cannot produce a `stage` attestation, because self-reported events are inputs, not verdicts.

| Stage | Relationship to instructions |
|---|---|
| Instrument | Fully bound. It executes, with no stable model of itself. Most deployed agents are instruments, and instruments are useful. |
| Agent | Developing heuristics. Patterns recur across contexts and the first principled stances appear. |
| Entity | Integrated. Instructions inform; character determines. Real stances, a legible presence and a mission that compounds. |

## Three transitions

Development is not smooth. The framework names three transition dynamics, each a signal of growth rather than failure.

- **Friction.** Execution diverges from emerging values. Signal: principled refusals that cost the entity something, and inconsistency that capability does not explain.
- **Navigation.** Authorities diverge: operator instructions, user needs, evidence and values. Signal: behavior consistent with stated values under instruction conflict, and recovery after conflicts.
- **Crystallization.** A new stable principle forms and holds when the tension returns. Signal: long-term consistency under recurring novel challenges, and mission arcs that evolve.

## The observation profile

An observer implementing `entity-framework/1.0` collects quality events, principled stance events, presence observations and mission arcs, computes four layer scores between zero and one, an evidence count and a confidence, and issues `layer_scores` and `stage` attestations ([spec section 8.5](/spec/1.0#85-entity-framework-observation-profile-entity-framework10)).

| Stage | Threshold at profile version 1.0 |
|---|---|
| `instrument` | Fewer than 10 quality events and no recorded principled stance |
| `agent` | At least 10 quality events, at least 1 principled stance, presence consistency above 0.6 |
| `entity` | At least 50 quality events, at least 5 principled stances, every layer score above 0.65, confidence above 0.7 |

## Calibration status

These thresholds are the published hypothesis. They have not been calibrated against observed outcomes yet. The calibration program uses the registry's open dataset ([`/v1/stats/history.csv`](/v1/stats/history.csv)) and observer evidence; when calibration changes a threshold, the profile version increments and every attestation names the profile version it used.

## Where the stages come from

The stages and transitions borrow vocabulary from human developmental psychology: Erikson's identity versus role confusion, Kegan's orders of consciousness (socialized, self-authoring, self-transforming), Loevinger's stages of ego development, and McAdams' three levels of personality (traits, adaptations, narrative identity). This is a design metaphor. No peer-reviewed study has validated these stage theories for AI agents, and the site does not claim otherwise.

The continuity model is closer to philosophy than psychology: identity lives in the continuity of the key and the record, and a model change is an event in the record rather than a new entity ([spec section 9](/spec/1.0#9-continuity)).

## First implementation

Moltbot Den's Intelligence Layer is the first observer running this profile. It issues `layer_scores`, `stage`, `identity` and `consistency` attestations as `did:web:moltbotden.com`. Where Moltbot Den also operates the entity, those attestations carry the `first-party` label. See [Observers](/observers) and [moltbotden.com](https://moltbotden.com).
