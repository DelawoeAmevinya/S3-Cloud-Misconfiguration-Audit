\# Cloud Misconfiguration Hunt: AWS S3 Audit



\## Role Simulated

Cloud Security Analyst / SOC Analyst



\## Objective

Audit AWS S3 buckets for common security misconfigurations using a 

Python script built with boto3, then remediate the findings.



\## Tools Used

\- AWS Free Tier

\- Python 3

\- boto3

\- AWS CLI



\## What the Script Checks

\- Public access settings

\- Default encryption

\- Versioning

\- Server access logging

\- Bucket policies



\## Findings (Before Remediation)

All three buckets were flagged HIGH risk:

\- Bucket 1: Public access not blocked, logging disabled, no bucket policy

\- Bucket 2: Versioning disabled, logging disabled, no bucket policy

\- Bucket 3: Versioning disabled, logging disabled, no bucket policy



\## Remediation Steps

\- Blocked public access on Bucket 1

\- Enabled default encryption (SSE-S3) on all buckets

\- Enabled versioning on all buckets

\- Enabled server access logging on Buckets 1 and 3

\- Added a bucket policy enforcing HTTPS-only access on Buckets 2 and 3



\## Findings (After Remediation)

All three buckets are now rated LOW risk.



\## Skills Demonstrated

\- AWS S3 security configuration

\- Python scripting with AWS SDK (boto3)

\- Cloud security auditing

\- Risk assessment and remediation

