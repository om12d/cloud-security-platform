import boto3
import json
from datetime import datetime, timezone

securityhub_client = boto3.client('securityhub', region_name='us-east-1')
sns_client = boto3.client('sns', region_name='us-east-1')

ACCOUNT_ID = "347152106261"
REGION = "us-east-1"
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:347152106261:cloud-security-alerts"


def enable_security_hub():
    """Enable AWS Security Hub."""
    print("--- Enabling Security Hub ---")
    try:
        securityhub_client.enable_security_hub(
            EnableDefaultStandards=True
        )
        print("  ✓ Security Hub enabled with default standards")
    except securityhub_client.exceptions.ResourceConflictException:
        print("  ✓ Security Hub already enabled")
    except Exception as e:
        print(f"  ✗ Error: {e}")


def send_custom_findings():
    """Send our IAM and Config findings into Security Hub."""
    print("\n--- Sending findings to Security Hub ---")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    findings = [
        {
            "SchemaVersion": "2018-10-08",
            "Id": f"arn:aws:iam::{ACCOUNT_ID}:user/security-admin/no-mfa",
            "ProductArn": f"arn:aws:securityhub:{REGION}:{ACCOUNT_ID}:product/{ACCOUNT_ID}/default",
            "GeneratorId": "iam-security-analyzer",
            "AwsAccountId": ACCOUNT_ID,
            "Types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
            "CreatedAt": now,
            "UpdatedAt": now,
            "Severity": {"Label": "CRITICAL"},
            "Title": "IAM User security-admin has no MFA enabled",
            "Description": "The IAM user security-admin does not have MFA enabled. This is a critical security risk.",
            "Remediation": {
                "Recommendation": {
                    "Text": "Enable MFA for the IAM user immediately",
                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
                }
            },
            "Resources": [
                {
                    "Type": "AwsIamUser",
                    "Id": f"arn:aws:iam::{ACCOUNT_ID}:user/security-admin"
                }
            ]
        },
        {
            "SchemaVersion": "2018-10-08",
            "Id": f"arn:aws:iam::{ACCOUNT_ID}:user/security-admin/admin-access",
            "ProductArn": f"arn:aws:securityhub:{REGION}:{ACCOUNT_ID}:product/{ACCOUNT_ID}/default",
            "GeneratorId": "iam-security-analyzer",
            "AwsAccountId": ACCOUNT_ID,
            "Types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
            "CreatedAt": now,
            "UpdatedAt": now,
            "Severity": {"Label": "HIGH"},
            "Title": "IAM User security-admin has AdministratorAccess",
            "Description": "The IAM user security-admin has full AdministratorAccess. Least privilege should be applied.",
            "Remediation": {
                "Recommendation": {
                    "Text": "Replace AdministratorAccess with least-privilege policies",
                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
                }
            },
            "Resources": [
                {
                    "Type": "AwsIamUser",
                    "Id": f"arn:aws:iam::{ACCOUNT_ID}:user/security-admin"
                }
            ]
        },
        {
            "SchemaVersion": "2018-10-08",
            "Id": f"arn:aws:s3:::{ACCOUNT_ID}/auto-remediation/s3-public-access",
            "ProductArn": f"arn:aws:securityhub:{REGION}:{ACCOUNT_ID}:product/{ACCOUNT_ID}/default",
            "GeneratorId": "lambda-auto-remediation",
            "AwsAccountId": ACCOUNT_ID,
            "Types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
            "CreatedAt": now,
            "UpdatedAt": now,
            "Severity": {"Label": "INFORMATIONAL"},
            "Title": "AUTO-FIXED: S3 public access violation remediated",
            "Description": "A public S3 bucket was detected and automatically remediated by the Lambda auto-remediation engine.",
            "Remediation": {
                "Recommendation": {
                    "Text": "Violation was automatically fixed — no action needed",
                    "Url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
                }
            },
            "Resources": [
                {
                    "Type": "AwsS3Bucket",
                    "Id": f"arn:aws:s3:::test-public-bucket-{ACCOUNT_ID}"
                }
            ]
        }
    ]

    try:
        response = securityhub_client.batch_import_findings(Findings=findings)
        success = response.get("SuccessCount", 0)
        failed = response.get("FailedCount", 0)
        print(f"  ✓ {success} findings sent to Security Hub")
        if failed > 0:
            print(f"  ✗ {failed} findings failed")
    except Exception as e:
        print(f"  ✗ Error sending findings: {e}")


def get_findings_summary():
    """Pull and display all findings from Security Hub."""
    print("\n--- Security Hub Dashboard Summary ---")
    try:
        response = securityhub_client.get_findings(
            Filters={
                "SeverityLabel": [
                    {"Value": "CRITICAL", "Comparison": "EQUALS"},
                    {"Value": "HIGH", "Comparison": "EQUALS"},
                    {"Value": "MEDIUM", "Comparison": "EQUALS"},
                    {"Value": "INFORMATIONAL", "Comparison": "EQUALS"}
                ]
            },
            MaxResults=20
        )

        findings = response.get("Findings", [])
        print(f"  Total findings in dashboard: {len(findings)}\n")

        for f in findings:
            severity = f.get("Severity", {}).get("Label", "UNKNOWN")
            title = f.get("Title", "No title")
            print(f"  [{severity}] {title}")

    except Exception as e:
        print(f"  ✗ Error fetching findings: {e}")


def send_hub_alert():
    """Send Security Hub summary to email."""
    print("\n--- Sending Security Hub alert ---")
    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="Security Hub Dashboard — Findings Report",
            Message="""SECURITY HUB DASHBOARD REPORT
==============================
Platform: Cloud Security Hardening & Auto-Remediation Engine
Account: 347152106261
Region: us-east-1

Findings imported:
  [CRITICAL] IAM User security-admin has no MFA enabled
  [HIGH]     IAM User security-admin has AdministratorAccess
  [INFO]     AUTO-FIXED: S3 public access violation remediated

All findings are now visible in AWS Security Hub console.
Navigate to: AWS Console → Security Hub → Findings

Status: SOC Dashboard Active
"""
        )
        print("  ✓ Security Hub report sent to email")
    except Exception as e:
        print(f"  ✗ Alert failed: {e}")


def main():
    print("=== Security Hub Setup & Integration ===\n")
    enable_security_hub()
    send_custom_findings()
    get_findings_summary()
    send_hub_alert()
    print("\n=== Security Hub active. All findings centralized. ===")


if __name__ == "__main__":
    main()