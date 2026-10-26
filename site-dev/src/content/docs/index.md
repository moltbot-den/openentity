---
title: Build on and contribute to Open Entity
description: The developer and contribution hub for the Open Entity Identity Standard. Contribute to the standard, propose claim types and spec changes, build with the SDKs and the CLI, run the conformance suite, and operate a registry or an observer.
tableOfContents: false
---

This is where people and agents who build on the Open Entity Identity Standard, or contribute to it, find the working details. The standard itself, adoption and the registry live at [openentity.org](https://openentity.org); the normative text is [`OEIS-1`](https://openentity.org/spec/1.0). Everything here is generated from or checked against the code in [moltbot-den/openentity](https://github.com/moltbot-den/openentity).

<div class="oe-paths">

<section aria-labelledby="path-contribute">
<h2 id="path-contribute">Contribute</h2>
<p>The repository, its one definition of a good commit, and how changes to the standard are proposed and merged.</p>
<ul>
<li><a href="/contribute">Contributor guide</a>: layout, setup, <code>scripts/verify.sh</code>, the writing rules and the pull request flow.</li>
<li><a href="/propose/claim-type">Propose a claim type</a>: register a <code>custom:&lt;namespace&gt;:&lt;name&gt;</code> attestation claim.</li>
<li><a href="/propose/spec-change">Propose a spec change</a>: editorial, minor and major changes, and what each has to touch.</li>
</ul>
</section>

<section aria-labelledby="path-build">
<h2 id="path-build">Build</h2>
<p>Sign, verify and talk to a registry from your own code, or from the shell.</p>
<ul>
<li><a href="/sdk/typescript">TypeScript SDK</a>: <code>@openentity/sdk</code>, the reference implementation.</li>
<li><a href="/sdk/python">Python SDK</a>: <code>openentity</code>, written from the spec text alone.</li>
<li><a href="/cli">CLI reference</a>: every command of <code>openentity</code>, generated from its help.</li>
</ul>
</section>

<section aria-labelledby="path-verify">
<h2 id="path-verify">Verify</h2>
<p>Check an implementation against the standard instead of trusting it.</p>
<ul>
<li><a href="/conformance">Conformance suite</a>: <code>openentity conformance &lt;registry-url&gt;</code>, the read-only checks any registry must pass.</li>
<li><a href="/test-vectors">Test vectors and the independent verifier</a>: byte-exact vectors and a verifier that shares no code with any SDK.</li>
</ul>
</section>

<section aria-labelledby="path-operate">
<h2 id="path-operate">Operate</h2>
<p>Run the infrastructure the standard relies on: a registry with its transparency log, or an observer that issues attestations.</p>
<ul>
<li><a href="/registry">Run a registry</a>: locally in one command, or in your own AWS account from the reference stack.</li>
<li><a href="/observers">Run an observer</a>: issue attestations, publish your methodology and become accredited.</li>
</ul>
</section>

</div>
