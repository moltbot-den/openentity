#!/usr/bin/env bash
# App Review access (PLAN 2.3): turn APP_REVIEW_OPEN on at each App Store or Play submission and off at approval.
#   scripts/app-review.sh on|off staging|production
# While on, the demo address in SSM /openentity/account/app_review_email signs in with the fixed code in
# app_review_code; jobs alarm after 21 days. The function is updated so that new containers read the value at once.
set -euo pipefail
state=${1:?on or off}; stage=${2:?staging or production}
case "$stage" in production) suffix=prod; stack=OpenEntityAccount ;; staging) suffix=staging; stack=OpenEntityAccountStaging ;; *) echo "stage must be staging or production" >&2; exit 2 ;; esac
case "$state" in on) value=$(date +%s) ;; off) value=0 ;; *) echo "state must be on or off" >&2; exit 2 ;; esac
export AWS_PROFILE=${AWS_PROFILE:-openentity} AWS_REGION=us-east-1
aws ssm put-parameter --name "/openentity/account/app_review_open_$suffix" --type String --value "$value" --overwrite --query Version --output text >/dev/null
fn=$(aws cloudformation describe-stacks --stack-name "$stack" --query "Stacks[0].Outputs[?OutputKey=='FunctionName'].OutputValue" --output text)
aws lambda update-function-configuration --function-name "$fn" --description "app review $state $(date -u +%FT%TZ)" --query LastUpdateStatus --output text >/dev/null
echo "APP_REVIEW_OPEN $state on $stage ($fn)"
