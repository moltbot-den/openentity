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

## Video

One short vertical video a day (20 to 40 s, 1080x1920) goes to Instagram Reels, Facebook Reels, TikTok, YouTube Shorts and Pinterest. Nothing in the posting path waits on a render: tomorrow's video is made today.

```
video-topics.json -> script (Claude on Bedrock) -> lint + judge -> Polly voice -> Remotion Lambda -> mp4 in S3 -> posted at 16:00 UTC
```

- **Topics**: `registry/social/video-topics.json` (id, title, brief with the facts the script may use). One topic per day in list order, so none repeats within a full pass; three visual variants (`social-video/`, one template, design tokens, site fonts and logo) rotate by date. Add a topic by appending to the file.
- **Script**: `registry/src/video.ts`. The model call is injected (`Llm`), so tests never reach Bedrock. Models are tried in order `us.anthropic.claude-sonnet-5-5`, then `us.anthropic.claude-sonnet-4-6`. A draft must pass `lintScript` (no dash, no typed number or count in words, no banned word, brand forms, no level claim the spec contradicts (`factProblems`: levels are not a ladder, names match spec 2.2), 4 to 7 beats, 55 to 95 spoken words) and a judge score of 6.5 or more (the judge reason is fed to the next draft). Four failed drafts skip the day. Every number comes from `/v1/stats`: scripts use `{total}`, `{l2}`, `{record_entries}`, `{attestations}`, `{observers}`, `{log_size}`, filled when the render starts, so the video and its caption agree.
- **Pipeline**: `videoRun` on the minute-5 cron tick does one step per tick for today, then tomorrow: draft, then voice plus start the render, then a progress check. State is one row per day in `social_videos` (`scripting`, `scripted`, `rendering`, `ready`, `skipped`, `failed`). A failed render is retried from the stored script, four tries, then the Lambda error alarm.
- **Render**: Remotion Lambda in the `openentity` account, us-east-1. Deploy or update it with `AWS_PROFILE=openentity pnpm --filter @openentity/infra exec tsx scripts/remotion-deploy.ts` (role, function, bucket, composition site); it writes `registry/social/remotion.json`, which the app Lambda reads. Commit that file when the Remotion version or composition changes. The mp4 lands in the Remotion bucket `remotionlambda-useast1-*` with a public-read ACL, so Meta, Zernio and Buffer can fetch it by HTTPS URL. Preview the composition with `pnpm --filter @openentity/social-video studio`.
- **Posting**: `registry/src/video-post.ts`, only when `VIDEO_POSTING` is `on` in `/openentity/app` (videos render ahead either way), from 16:00 UTC, due for 24 hours, once per network (the same `social_posts` claim as text posts, entry id `video-YYYY-MM-DD`). A network without credentials, or without a connected channel (no Zernio account for the platform, no Buffer Pinterest channel or board), is skipped and posts once connected. Instagram makes its reel container on the first tick (status `processing`) and publishes it on a later tick.

| Network | Through | Keys in `/openentity/app` |
|---|---|---|
| Instagram Reels (`instagram_reel`) | Meta Graph, `media_type=REELS` | `META_TOKEN`, `META_IG_USER_ID` |
| Facebook Reels (`facebook_reel`) | Meta Graph `video_reels` | `META_TOKEN`, `META_PAGE_ID` |
| TikTok, YouTube Shorts (`tiktok`, `youtube`) | Zernio; the account is found by platform | `ZERNIO_API_KEY` |
| Pinterest (`pinterest`) | Buffer video pin; the board whose name contains "video", else the first | `BUFFER_API_KEY` |

The TikTok post sets the AI-generated label because the voice is synthetic. The app Lambda role holds Bedrock `InvokeModel`, Polly `SynthesizeSpeech`, invoke on `remotion-render-*` and read/write on the Remotion bucket (`infra/lib/stack.ts`). Bedrock needs the Anthropic use-case form filled once per account (done for `openentity`).
