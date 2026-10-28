# Outreach sent

All mail goes out from `Open Entity <identity@openentity.org>` (reply-to the same) through Customer.io transactional (`POST /v1/send/email`), because SES is still in the sandbox (production access denied, case 179315664200715; a new request is rejected with ConflictException while that case is closed). The id is the Customer.io delivery id. Replies land in the S3 mailbox (`docs/MAILBOX.md`).

| Date (UTC) | Recipient | Subject | Delivery id |
| --- | --- | --- | --- |
| 2026-10-28 | wellknown-uri-review@ietf.org | Request for well-known URI: openentity.json | RLvEDgUAAaGAgviyd7Bid6zXLrCtYQ== |
| 2026-10-28 | wimse-request@ietf.org (subscribe, confirmed; welcome mail received) | subscribe | RLvEDgUAAaGAgyXuzxD7FXD3VWcA0Q== |
| 2026-10-28 | wimse@ietf.org | Input on AI agent identity across organizations: OEIS-1 (continuity, record, attestations) | RLvEDgUAAaGAhMvt8TL3cgmky3zVaw== |
| 2026-10-28 | public-agent-identity-request@w3.org (subscribe) | subscribe | RLvEDgUAAaGAgyCoG20vdryMvoAH1g== |
| 2026-10-28 | public-agent-identity@w3.org | Contribution: Open Entity Identity Standard (OEIS-1), continuity and development record for agent identifiers | RLvEDgUAAaGAhRhepdih-TbWa-dqpw== |

Notes

- Status check 2026-10-28 (late): no reply to any of the five sends in the mailbox or the public archives. The wellknown-uri-review archive (mailarchive.ietf.org) shows nothing after 2026-10-07 and the W3C `public-agent-identity` archive does not yet list our post; the IETF archive search sits behind a bot challenge, so the list traffic in the mailbox is the check. Nothing to answer.
- IANA: not approved (no designated expert response), nothing registered. Next step stays the request form once the expert answers.
- mcpservers.org: listed (Open Entity appears on https://mcpservers.org/remote-mcp-servers). No resubmission needed.
- SES: production access still DENIED (case 179315664200715, closed). `aws sesv2 put-account-details` with a full use case on 2026-10-28 returned ConflictException again, and the support API needs a Premium Support plan. Mail keeps going through Customer.io.
- W3C Community Group: the browser is not signed in to w3.org (Sign in shown), so the group was not joined and no agreement was accepted.
- IANA: the next step after list review is the IANA request form for the Well-Known URIs registry, once the designated expert answers.
- W3C: the list is open to anyone to write. Formal Community Group membership (and the contributor agreement) needs a W3C account, which an agent may not create: https://www.w3.org/accounts/request
- Launch posts (`LAUNCH-POSTS.md`) are queued for the herald loop, which posts when the accounts exist.
- AAIF (`AAIF-DRAFT.md`) stays a draft and is not submitted.
