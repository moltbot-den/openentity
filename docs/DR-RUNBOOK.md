# Disaster recovery runbook

Last drill: 2026-10-27 UTC (account `openentity`, 099705791378, us-east-1, profile `openentity`). Everything below marked "drilled" was run for real against a scratch bucket and a scratch cluster; production was only read.

## What is backed up where

| Data | Where | Protection |
| --- | --- | --- |
| Log tiles (`tile/0/...`, `tile/entries/...`), `checkpoint`, a copy of each daily snapshot | S3 log bucket (stack output `LogBucketName`, `openentity-logbucket...`) | Versioning on, retained on stack delete, S3-managed encryption. The registry can regenerate it from the database. |
| Daily snapshots `snapshots/<YYYY-MM-DD>.jsonl` and signed objects `objects/<YYYY-MM-DD>.jsonl` | S3 snapshot bucket (`SnapshotBucketName`, `openentity-snapshotbucket...`) | Object Lock, compliance mode, 365 days default retention, versioning, retained on stack delete. Written once a day by the cron for the previous UTC day (the objects file right after the snapshot). |
| Entities, documents, declarations, record entries, attestations, aliases, continuity links, leaves, nodes, checkpoints | Aurora Serverless v2 PostgreSQL (cluster `openentity-db...`) | Encrypted, 14 days automated backups with point-in-time restore, deletion protection on. |
| Registry signing key, custody key, Customer.io and Turnstile secrets | Secrets Manager `openentity/app` | The signing key also has a backup in GCP Secret Manager (PRD section 7). |

A daily snapshot holds one JSON line per log leaf received that day (`index`, `leaf`, `leaf_hash`) and a last line with the latest checkpoint (`tree_size`, `root_hash`, `timestamp`, `signed_note`). A day with no new leaves holds only the checkpoint line. Leaves are what the log commits to: type, EID, SHA-256 of the signed object and receive time. The signed objects are in the matching `objects/<date>.jsonl`: one line per leaf, `{idx, type, eid, object_sha256, object}`, where the sha256 of the canonical `object` equals `object_sha256` (a leaf whose object the database no longer held is left out and logged). Entity Documents, Declarations, record entries, Redactions, Withdrawals, attestations, Revocations, continuity links, disputes and aliases are all there. A redacted record entry is exported as its placeholder (`redacted`, `hash`, `redaction`), never its content; its `hash` is the leaf's `object_sha256`.

## Verify (the check that proves a restore)

`scripts/rebuild_check.py` is the rebuild check (it reuses the code of the independent verifier). Point it at a directory laid out like the log bucket (`snapshots/`, `tile/`):

    uv run scripts/rebuild_check.py https://openentity.org DIR

It fetches the live checkpoint and verifies its Ed25519 signature against the key in `/v1/spec`. Then it reads every leaf from `DIR/snapshots/*.jsonl` (leaves must be contiguous from 0 and agree across files), recomputes each leaf hash, recomputes the RFC 6962 root at the size of every embedded snapshot checkpoint, byte-compares the level 0 hash tiles and the entry bundles under `DIR/tile` with the rebuilt leaves, and compares the rebuilt root at the live size with the signed root. It exits 1 on any mismatch. If `DIR/objects/*.jsonl` exists it also checks every line against its leaf (type, EID, hash) and reports how many leaves have a matching object. Tiles missing from the copy are reported as skipped; leaves are the authority.

## Restore the log bucket into a fresh bucket

    B=openentity-restore-$(date +%Y%m%d)
    aws s3api create-bucket --bucket $B
    aws s3api put-public-access-block --bucket $B --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
    aws s3 sync s3://<log bucket>/ s3://$B/
    aws s3 sync s3://<snapshot bucket>/snapshots/ s3://$B/snapshots/   # fills days the log bucket copy lacks
    aws s3 sync s3://<snapshot bucket>/objects/ s3://$B/objects/

To rebuild instead of copy (log bucket lost, snapshots intact), put every snapshot in `DIR/snapshots/` and run the verify command above. The tiles are a pure function of the leaves: level 0 tile N holds the 32-byte leaf hashes 256*N to 256*N+255, an entry bundle holds each leaf as a big-endian uint16 length plus canonical JSON, partial tiles live at `<tile>.p/<count>`. A fresh registry regenerates all of them with `incorporate()` once `log_leaves` is filled (next section).

## Restore the database into a fresh cluster

Drilled: point-in-time restore of the live cluster. The restore needs the DB subnet group and security group of the live cluster; the Lambda reaches the cluster only through the Data API, so the Data API must be enabled on the restored cluster.

    aws rds restore-db-cluster-to-point-in-time \
      --db-cluster-identifier openentity-restore --source-db-cluster-identifier <live cluster id> \
      --use-latest-restorable-time --restore-type full-copy \
      --db-subnet-group-name <live subnet group> --vpc-security-group-ids <live sg> \
      --serverless-v2-scaling-configuration MinCapacity=0.5,MaxCapacity=4
    aws rds create-db-instance --db-instance-identifier openentity-restore-writer \
      --db-cluster-identifier openentity-restore --engine aurora-postgresql --db-instance-class db.serverless
    aws rds wait db-instance-available --db-instance-identifier openentity-restore-writer
    aws rds enable-http-endpoint --resource-arn <restored cluster arn>

`restore-db-cluster-to-point-in-time` has no `--enable-http-endpoint` flag and `modify-db-cluster --enable-http-endpoint` does not take effect; use `enable-http-endpoint`. Pass `--restore-time <ISO time>` instead of `--use-latest-restorable-time` to pick a moment, or use `restore-db-cluster-from-snapshot` with an automated snapshot (`aws rds describe-db-cluster-snapshots`). The restored cluster keeps the source master credentials, so the existing `DB_SECRET_ARN` secret works against it. Check it:

    aws rds-data execute-statement --resource-arn <restored cluster arn> --secret-arn <DB_SECRET_ARN> --database openentity \
      --sql "SELECT max(tree_size), (SELECT root_hash FROM checkpoints ORDER BY tree_size DESC LIMIT 1) FROM checkpoints"

Compare that root with `curl -s https://openentity.org/v1/log/checkpoint` (second line is the size, third the root, base64) or with the hex root the verifier prints. Then point the app at the new cluster: set `DB_CLUSTER_ARN` on the app Lambda to the restored cluster (`aws lambda update-function-configuration`), and bring the CDK stack in line with `cdk import` or by changing the stack to use the restored cluster, so the next deploy does not revert it.

If the database is lost beyond the 14 day window, rebuild it from the snapshot bucket alone. Download `snapshots/` and `objects/` to `DIR` and run the verify command first: PASS proves the leaves and the objects are intact. Then, with the schema applied (`registry/schema.sql`):

1. Insert each snapshot line into `log_leaves (idx, leaf_hash, type, eid, object_sha256, received_at)` (`index`, `leaf_hash` and the `leaf` fields), the last checkpoint row into `checkpoints`, and set `log_head.next` to the tree size. Run the cron once; `log_nodes` fills from `incorporate()` for the leaves, so insert level 0 nodes and recompute the parents from the verifier's tree for a full rebuild.
2. Replay `objects/*.jsonl` in `idx` order. Per type, with `json` the canonical JSON of `object`, `sha256` the line's `object_sha256`, `received_at` the leaf's, `log_index` the line's `idx`:
   - `EntityDocument`: `documents (eid, seq, json, sha256, received_at, log_index)`; the highest `seq` per EID is the entity's `latest_seq` and `name`.
   - `Declaration`: `declarations (eid, version, ...)`; a later `Withdrawal` line sets that row's `withdrawn_at` (its leaf time) and `withdrawal_json`, and the entity's `withdrawn_at`.
   - `RecordEntry`: `record_entries (eid, seq, kind, ...)`; a redacted placeholder is inserted as is. The entity's `record_seq` and `record_head_hash` are the last entry's `seq` and sha256. A `Redaction` line needs no row of its own: its placeholder already carries it.
   - `Attestation`: `attestations`; a `Revocation` line sets `revoked_at` and `revocation_json` on the attestation named by its `attestation_sha256`.
   - `ContinuityLink`: `continuity_links`; `Dispute`: `disputes`; `Alias`: `aliases` with `proof_json` = `object.proof`, status `verified`.
3. Recompute `entities.level` (the registry does it on each write) by re-saving each entity's latest document, or run the level refresh from `registry/src/index.ts` over every EID.

Not drilled end to end: the replay SQL above is the documented procedure, the hash checks are tested.

## Measured in the drill

All times wall clock from a laptop on the home network, log of 41 leaves (about 100 KB).

| Step | Time |
| --- | --- |
| Create scratch bucket with public access blocked | 1.5 s |
| Copy both production buckets into the scratch bucket (40 objects) | 2.6 s |
| Download the scratch copy and run the rebuild verification | 1.4 s and 0.4 s |
| Aurora point-in-time restore request to instance available | 8 min 36 s |
| Enable Data API to first successful query | about 1 min 40 s |
| Total to a queryable restored database | about 10 min 20 s |

Aurora time grows with data size; the database was a few MB. Budget 15 minutes plus the Lambda and CDK repoint.

## Drill result

- Live checkpoint: size 41, root (hex) `fa712327235552b2af01b590a6ed412897952d473fda7d70aa9d31b6b8070cce`, signature verified against the registry key.
- Rebuilt from snapshots of both buckets: size 41, same root. Rebuilt root also matched the root recorded in each of the four snapshots (sizes 5, 5, 41, 41) and the level 0 tile and entry bundle for 41 leaves matched byte for byte. Result PASS.
- Rebuilt from the snapshot bucket alone: FAIL, leaf 0 in no snapshot (36 leaves found, see Gaps).
- No tiles beyond the snapshot tree size were needed: the snapshot and the live checkpoint are both at size 41.
- Restored Aurora (latest restorable time): 41 leaves, checkpoint size 41, root equal to the live root, 9 entities.
- The drill found and fixed one defect: the snapshot of a day with no new leaves started with a blank line, which strict JSONL readers reject. `snapshot()` no longer emits it, and the verifier skips blank lines so existing files (for example 2026-10-26) still verify.

## Gaps

1. Closed 2026-10-26. The owner copied the 2026-10-23 and 2026-10-24 snapshots into the Object Lock bucket; the Object Lock copy alone now verifies leaves 0 to 40.
2. Closed 2026-10-26. The daily job writes `objects/<date>.jsonl` next to each snapshot (same Object Lock bucket), and a one-off `backfill-objects` job wrote every earlier day. To rerun it (idempotent, it only writes missing days): `aws lambda invoke --function-name <app function> --cli-binary-format raw-in-base64-out --payload '{"source":"openentity.job","job":"backfill-objects"}' out.json`.
3. The leaves-and-objects database rebuild above is documented but not drilled. Aurora backups are in the same account and region as the cluster; a cross-region copy is not set up.
