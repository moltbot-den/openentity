# Social publisher

`registry/src/social.ts` posts `registry/social/calendar.json` from the app Lambda's cron (minute 5 of every ten). Each entry goes to every network whose credentials are in `/openentity/app`, once, within 24 hours of its `at` time. `{total}`, `{l2}`, `{record_entries}`, `{attestations}`, `{observers}` and `{log_size}` are filled from `/v1/stats` at post time. Every attempt is a row in `social_posts` (`posted` with the network's id, or `failed` with the error; a failed send is not retried).

| Network | Through | Keys in `/openentity/app` |
|---|---|---|
| Facebook Page | Meta Graph API | `META_TOKEN`, `META_PAGE_ID` |
| Instagram (business account linked to the Page) | Meta Graph API, image `https://openentity.org/og.jpg` unless the entry sets `image` | `META_TOKEN`, `META_IG_USER_ID` |
| X, Threads, LinkedIn | Buffer GraphQL (Open Entity organization, free plan: 3 channels) | `BUFFER_API_KEY` |
| Bluesky | atproto, app password | `BLUESKY_HANDLE`, `BLUESKY_APP_PASSWORD` |

`META_TOKEN` is a Meta Business system user token with the Open Entity Page and its Instagram account assigned (`pages_manage_posts`, `pages_read_engagement`, `instagram_basic`, `instagram_content_publish`).

Adding a post: append `{ "id", "at", "text" }` to the calendar in a PR. The calendar test fails on a duplicate id, a bad time, an em dash or a field stats cannot fill. Check what went out:

```sql
SELECT entry_id, platform, status, ref, error FROM social_posts ORDER BY at DESC LIMIT 20;
```
