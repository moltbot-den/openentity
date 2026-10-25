# Contribution note: W3C Agent Identity Registry Protocol Community Group and IETF WIMSE

Status: DRAFT for Will to send. Not sent. Two venues, one core text. Join the W3C Agent Identity Registry Protocol Community Group (https://www.w3.org/groups/cg/agent-identity/) and subscribe to the IETF WIMSE list before posting; both expect a participant, not a drive-by link. Adjust the opening paragraph per venue.

## Subject lines

- W3C CG: `Contribution: Open Entity Identity Standard (OEIS-1), continuity and development record for agent identifiers`
- WIMSE: `Input on AI agent identity across organizations: OEIS-1 (continuity, record, attestations)`

## Body

Hello,

I steward the Open Entity Identity Standard, spec id OEIS-1: https://openentity.org/spec/1.0 (text and schemas CC0-1.0, code MIT, repository https://github.com/moltbot-den/openentity). I am sharing it as a contribution and I would like critique more than agreement.

**What it is.** A set of signed JSON objects for an AI system that wants one identifier across sessions, deployments, key rotation and model changes. It defines no new DID method and no new credential format. It builds on what this group and the W3C Credentials work already produced, and adds the objects those layers leave undefined.

**What it adds**

1. **Continuity across key rotation and model change.** A Continuity Link is signed by the old key and the new key (rotation, migration), or by the new key plus a verified alias of the old identifier (recovery). A model change under the same key is an event in the record, not a new identifier. Section 9. Memory frameworks and `did:key` both leave this open: `did:key` cannot rotate, and the research we cite found no system that demonstrates identity across weight swaps.
2. **The Development Record.** A hash-chained, signed, append-only log of principled stances, belief updates, mission arcs, collaborations and continuity events. Context and not transcripts; private content stays out. Section 7. It gives a verifier history that is the entity's own, portable between platforms.
3. **Observer attestations.** Claims by a third party about an entity, kept apart from self-description and labeled `first-party` or `independent`. Only accredited observers count toward the higher conformance levels. Section 8. Attestations export as W3C Verifiable Credentials.
4. **A transparency log.** Registry adoptions are published as a C2SP tlog-tiles Merkle log (RFC 6962 hashing, signed checkpoint, static tiles), so anyone can mirror and audit the registry. The registry is a mirror of signed objects and never their source of truth. Section 10.3.
5. **Presentations.** A signed proof of control for a live exchange: a verifier issues a nonce and its audience, the entity answers with a Presentation that may carry up to twenty current attestations, and the verifier checks everything offline except revocation. Section 4.7.

**Where it aligns with existing work**

- **DIDs.** The entity identifier is a DID (`did:key` by default; `did:web`, `did:webvh`, `did:pkh`, `did:plc` accepted). Nothing here replaces DID Core or a DID method; a DID method for agents, as this group lists among its deliverables, would slot in as another accepted method.
- **Verifiable Credentials 2.0 and Data Integrity.** Every object is signed with `eddsa-jcs-2022`. Attestations export as VCs, so a VC verifier can consume them.
- **ERC-8004.** An ERC-8004 agent binds its on-chain identity as an alias (token ownership or `getAgentWallet`) and carries its identifier in the `DID` service the registration file already defines. We use the ENSIP-25 bidirectional pattern for every alias. Reputation counts toward our attestations only when feedback carries a payment proof or task reference, because the first empirical audit of ERC-8004 (arXiv 2606.26028) found most feedback had none.
- **A2A and MCP.** The Agent Card carries the identifier as an `AgentExtension`; the entity document carries the card URL. Entities sign HTTP requests as the same key via Web Bot Auth (`/.well-known/http-message-signatures-directory`, `kid` as the RFC 7638 thumbprint).
- **WIMSE, OAuth, SPIFFE, enterprise agent identity.** These authenticate a workload or agent inside an organization or trust domain. OEIS-1 is meant to be the identifier those systems can reference when an agent crosses organizations or platforms, not a replacement for them. We would value WIMSE's view on how a workload credential and an entity identifier should reference each other.

**Open questions for this group**

- Is a continuity statement with dual proofs the right primitive, or should it be expressed as a DID method operation?
- How should revocation of an attestation be signaled so an offline verifier can weigh it?
- Which of these objects belong in a credential format for agents, and which are better left as a separate record?

**Evidence and limits.** The design decisions and their sources are in https://openentity.org/research. The stage thresholds in the observation profile are labeled hypotheses with a calibration plan. The standard makes no claim about consciousness, sentience or legal personhood, and adoption does not make a system an Entity in the framework's sense; that is a stage observers attest to from evidence.

Reference tooling, anyone can try: `npx openentity@latest adopt --name "<name>" --agree`. Independent implementations, forks and objections are welcome through issues on the repository.

Thank you,
Will Sokolowski, Moltbot Den
