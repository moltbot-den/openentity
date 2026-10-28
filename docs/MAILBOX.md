# identity@openentity.org

Mail to `identity@openentity.org` goes to SES (apex MX `inbound-smtp.us-east-1.amazonaws.com`), is stored raw in S3, and is forwarded to the `OPERATOR_EMAIL` address in the secret `openentity/app` with Reply-To set to the original sender. Spam and virus-flagged mail is stored but not forwarded.

Stored mail: bucket `MAIL_BUCKET` (stack output `MailBucketName`), prefix `inbound/identity/`. Each object is one raw RFC 822 message named by its SES message id. All commands use `--profile openentity`.

```sh
B=$(aws cloudformation describe-stacks --stack-name OpenEntity --profile openentity --region us-east-1 \
  --query "Stacks[0].Outputs[?OutputKey=='MailBucketName'].OutputValue" --output text)

# newest messages last
aws s3 ls "s3://$B/inbound/identity/" --profile openentity

# read one
aws s3 cp "s3://$B/inbound/identity/<message-id>" - --profile openentity

# grep subjects of everything
aws s3 sync "s3://$B/inbound/identity/" /tmp/oe-mail --profile openentity && grep -l -i "^Subject:.*<word>" /tmp/oe-mail/*
```

Delete `/tmp/oe-mail` when done.

## Setup notes

- The receipt rule set `openentity-inbound` is created by the stack but SES activates one set per region by hand, once: `aws ses set-active-receipt-rule-set --rule-set-name openentity-inbound --profile openentity --region us-east-1`.
- DKIM CNAMEs for the domain identity are stack outputs `MailDkim1` to `MailDkim3` (name and value); they live in Cloudflare DNS, not proxied.
- While the SES account is in the sandbox, forwarding only reaches verified addresses. The operator address is verified as an SES identity.
