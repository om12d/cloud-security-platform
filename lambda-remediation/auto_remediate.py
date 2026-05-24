import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
ec2_client = boto3.client('ec2')
sns_client = boto3.client('sns', region_name='us-east-1')

SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:347152106261:cloud-security-alerts"


def send_alert(subject, message):
    """Send SNS alert — reusing your Project 1 SNS topic."""
    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
        print(f"  ✓ Alert sent: {subject}")
    except Exception as e:
        print(f"  ✗ Alert failed: {e}")


def fix_public_s3_bucket(bucket_name):
    """Block all public access on an S3 bucket."""
    print(f"\n  Fixing public S3 bucket: {bucket_name}")
    try:
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        )
        print(f"  ✓ Blocked all public access on: {bucket_name}")
        send_alert(
            subject=f"AUTO-FIXED: S3 bucket {bucket_name} was public",
            message=f"VIOLATION DETECTED & AUTO-FIXED\n\nBucket: {bucket_name}\nViolation: Public access was enabled\nAction taken: All public access blocked automatically\nStatus: RESOLVED"
        )
        return True
    except Exception as e:
        print(f"  ✗ Failed to fix {bucket_name}: {e}")
        return False


def fix_open_ssh_security_group(group_id):
    """Remove SSH 0.0.0.0/0 rule from a security group."""
    print(f"\n  Fixing security group: {group_id}")
    try:
        ec2_client.revoke_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }
            ]
        )
        print(f"  ✓ Removed open SSH rule from: {group_id}")
        send_alert(
            subject=f"AUTO-FIXED: Security group {group_id} had open SSH",
            message=f"VIOLATION DETECTED & AUTO-FIXED\n\nSecurity Group: {group_id}\nViolation: SSH open to 0.0.0.0/0\nAction taken: Ingress rule removed automatically\nStatus: RESOLVED"
        )
        return True
    except Exception as e:
        print(f"  ✗ Failed to fix {group_id}: {e}")
        return False


def simulate_violations():
    """
    Simulate violations to test auto-remediation.
    Creates a public S3 bucket then immediately fixes it.
    """
    print("\n=== Simulating violations for testing ===")
    test_bucket = f"test-public-bucket-347152106261"

    # Create a test bucket
    try:
        s3_client.create_bucket(Bucket=test_bucket)
        print(f"  ✓ Created test bucket: {test_bucket}")

        # Make it public (this is the violation)
        s3_client.put_public_access_block(
            Bucket=test_bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False
            }
        )
        print(f"  ✓ Made bucket public (simulating violation)")

        # Now auto-remediate it
        fix_public_s3_bucket(test_bucket)

        # Clean up test bucket
        s3_client.delete_bucket(Bucket=test_bucket)
        print(f"  ✓ Cleaned up test bucket")

    except Exception as e:
        print(f"  ✗ Simulation error: {e}")


def main():
    print("=== Lambda Auto-Remediation Engine ===\n")
    print("Scanning for active violations...\n")

    fixed = 0

    # Check all S3 buckets for public access
    print("--- Checking S3 buckets ---")
    buckets = s3_client.list_buckets().get("Buckets", [])
    for bucket in buckets:
        name = bucket["Name"]
        try:
            block = s3_client.get_public_access_block(Bucket=name)
            config = block["PublicAccessBlockConfiguration"]
            is_public = not all([
                config.get("BlockPublicAcls"),
                config.get("IgnorePublicAcls"),
                config.get("BlockPublicPolicy"),
                config.get("RestrictPublicBuckets")
            ])
            if is_public:
                print(f"  ⚠ VIOLATION: {name} has public access enabled")
                if fix_public_s3_bucket(name):
                    fixed += 1
            else:
                print(f"  ✓ {name} — compliant")
        except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
            print(f"  ⚠ VIOLATION: {name} has no public access block")
            if fix_public_s3_bucket(name):
                fixed += 1
        except Exception as e:
            print(f"  ✗ Could not check {name}: {e}")

    # Check security groups for open SSH
    print("\n--- Checking security groups ---")
    sgs = ec2_client.describe_security_groups().get("SecurityGroups", [])
    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            if rule.get("FromPort") == 22:
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        print(f"  ⚠ VIOLATION: {sg['GroupId']} allows SSH from anywhere")
                        if fix_open_ssh_security_group(sg["GroupId"]):
                            fixed += 1

    print(f"\n=== Remediation complete: {fixed} violations auto-fixed ===")

    # Run simulation to prove the engine works
    simulate_violations()


if __name__ == "__main__":
    main()