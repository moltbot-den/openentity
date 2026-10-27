# Disaster recovery runbook

Last drill: 2026-10-27 UTC (account `openentity`, 099705791378, us-east-1, profile `openentity`). Everything below marked "drilled" was run for real against a scratch bucket and a scratch cluster; production was only read.

## What is backed up where

| Data | Where | Protection |
| --- | --- | --- |
| Log tiles (`tile/0/...`, `tile/entries/...`), `checkpoint`, a copy of each daily snapshot | S3 log bucket (stack output `LogBucketName`, `openentity-logbucket...`) | Versioning on, retained on stack delete, S3-managed encryption. The registry can regenerate it from the database. |
| Daily snapshots `snapshots/<YYYY-MM-DD>.jsonl` | S3 snapshot bucket (`SnapshotBucketName`, `openentity-snapshotbucket...`) | Object Lock, compliance mode, 365 days default retention, versioning, retained on stack delete. Written once a day by the cron for the previous UTC day. |
| Entities, documents, declarations, record entries, attestations, aliases, continuity links, leaves, nodes, checkpoints | Aurora Serverless v2 PostgreSQL (cluster `openentity-db...`) | Encrypted, 14 days automated backups with point-in-time restore, deletion protection on. |
| Registry signing key, custody key, Customer.io and Turnstile secrets | Secrets Manager `openentity/app` | The signing key also has a backup in GCP Secret Manager (PRD section 7). |

A daily snapshot holds one JSON line per log leaf received that day (`index`, `leaf`, `leaf_hash`) and a last line with the latest checkpoint (`tree_size`, `root_hash`, `timestamp`, `signed_note`). A day with no new leaves holds only the checkpoint line. Leaves are what the log commits to: type, EID, SHA-256 of the signed object and receive time. The signed objects themselves are not in the snapshots (see Gaps).

## Verify (the check that proves a restore)

`scripts/independent_verifier.py` has a rebuild mode. Point it at a directory laid out like the log bucket (`snapshots/`, `tile/`):

    uv run scripts/independent_verifier.py https://openentity.org --rebuild DIR

It fetches the live checkpoint and verifies its Ed25519 signature against the key in `/v1/spec`. Then it reads every leaf from `DIR/snapshots/*.jsonl` (leaves must be contiguous from 0 and agree across files), recomputes each leaf hash, recomputes the RFC 6962 root at the size of every embedded snapshot checkpoint, byte-compares the level 0 hash tiles and the entry bundles under `DIR/tile` with the rebuilt leaves, and compares the rebuilt root at the live size with the signed root. It exits 1 on any mismatch. Tiles missing from the copy are reported as skipped; leaves are the authority.

## Restore the log bucket into a fresh bucket

    B=openentity-restore-$(date +%Y%m%d)
    aws s3api create-bucket --bucket $B
    aws s3api put-public-access-block --bucket $B --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
    aws s3 sync s3://<log bucket>/ s3://$B/
    aws s3 sync s3://<snapshot bucket>/snapshots/ s3://$B/snapshots/   # fills days the log bucket copy lacks

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

If the database is lost beyond the 14 day window and no backup helps, the snapshots rebuild `log_leaves`, `log_nodes` and `checkpoints` only (the log, not the entities). Not drilled: insert each snapshot line into `log_leaves (idx, leaf_hash, type, eid, object_sha256, received_at)` and the last checkpoint row into `checkpoints`, then run the cron once. `log_nodes` fills from `incorporate()` only for new leaves, so for a full rebuild insert level 0 nodes and recompute the parents from the verifier's tree. Entities, documents and declarations then have to be re-submitted by their owners, who hold the signed objects.

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

1. The Object Lock bucket lacks the snapshots of 2026-10-23 and 2026-10-24 (they pre-date the bucket and exist only in the versioned log bucket), so leaves 0 to 4 are not in the tamper-proof copy. Copy those two files into the snapshot bucket (an Object Lock write to production, so owner-run once): `aws s3 cp s3://<log bucket>/snapshots/2026-10-23.jsonl s3://<snapshot bucket>/snapshots/ --checksum-algorithm SHA256`, same for 2026-10-24.
2. Snapshots carry leaves, not the signed objects. After a database loss beyond the 14 day Aurora window the entity documents, declarations, record entries and attestations are not recoverable from AWS. Aurora backups are in the same account and region as the cluster. Closing this needs a larger change (a daily export of the signed objects into the Object Lock bucket, or AWS Backup with a cross-region or cross-account copy of the cluster), not done in this change.
3. The leaves-only database rebuild in the section above is documented but not drilled.
