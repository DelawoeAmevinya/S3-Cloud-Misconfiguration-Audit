import boto3
import json

s3 = boto3.client('s3')

def audit_bucket(bucket_name):
    findings = {"bucket": bucket_name, "issues": []}

    # 1. Check Public Access Block settings
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        config = pab['PublicAccessBlockConfiguration']
        if not all(config.values()):
            findings["issues"].append("Public access NOT fully blocked")
    except s3.exceptions.ClientError:
        findings["issues"].append("No Public Access Block configuration found")

    # 2. Check Encryption
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
    except s3.exceptions.ClientError:
        findings["issues"].append("Encryption NOT enabled")

    # 3. Check Versioning
    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
    if versioning.get('Status') != 'Enabled':
        findings["issues"].append("Versioning NOT enabled")

    # 4. Check Logging
    logging_config = s3.get_bucket_logging(Bucket=bucket_name)
    if 'LoggingEnabled' not in logging_config:
        findings["issues"].append("Server access logging NOT enabled")

    # 5. Check Bucket Policy
    try:
        s3.get_bucket_policy(Bucket=bucket_name)
    except s3.exceptions.ClientError:
        findings["issues"].append("No bucket policy set")

    # Risk ranking
    if len(findings["issues"]) >= 3:
        findings["risk"] = "HIGH"
    elif len(findings["issues"]) >= 1:
        findings["risk"] = "MEDIUM"
    else:
        findings["risk"] = "LOW"

    return findings


def main():
    response = s3.list_buckets()
    all_findings = []

    for bucket in response['Buckets']:
        name = bucket['Name']
        result = audit_bucket(name)
        all_findings.append(result)
        print(f"\nBucket: {result['bucket']}")
        print(f"Risk: {result['risk']}")
        for issue in result['issues']:
            print(f"  - {issue}")

    # Save findings to JSON file
    with open('findings.json', 'w') as f:
        json.dump(all_findings, f, indent=4)

if __name__ == "__main__":
    main()