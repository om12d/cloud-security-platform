import boto3
import json

config_client = boto3.client('config', region_name='us-east-1')

RULES = [
    {
        "name": "s3-bucket-public-read-prohibited",
        "description": "S3 buckets must not allow public read access",
        "source": "S3_BUCKET_PUBLIC_READ_PROHIBITED",
        "severity": "CRITICAL"
    },
    {
        "name": "s3-bucket-public-write-prohibited",
        "description": "S3 buckets must not allow public write access",
        "source": "S3_BUCKET_PUBLIC_WRITE_PROHIBITED",
        "severity": "CRITICAL"
    },
    {
        "name": "root-account-mfa-enabled",
        "description": "Root account must have MFA enabled",
        "source": "ROOT_ACCOUNT_MFA_ENABLED",
        "severity": "CRITICAL"
    },
    {
        "name": "iam-user-mfa-enabled",
        "description": "All IAM users must have MFA enabled",
        "source": "IAM_USER_MFA_ENABLED",
        "severity": "HIGH"
    },
    {
        "name": "restricted-ssh",
        "description": "Security groups must not allow SSH from 0.0.0.0/0",
        "source": "RESTRICTED_INCOMING_TRAFFIC",
        "input_parameters": {"blockedPort1": "22"},
        "severity": "HIGH"
    },
    {
        "name": "encrypted-volumes",
        "description": "EBS volumes must be encrypted at rest",
        "source": "ENCRYPTED_VOLUMES",
        "severity": "MEDIUM"
    }
]


def create_rule(rule):
    config_rule = {
        "ConfigRuleName": rule["name"],
        "Description": rule["description"],
        "Source": {
            "Owner": "AWS",
            "SourceIdentifier": rule["source"]
        }
    }

    if "input_parameters" in rule:
        config_rule["InputParameters"] = json.dumps(rule["input_parameters"])

    try:
        config_client.put_config_rule(ConfigRule=config_rule)
        print(f"  ✓ Created rule: {rule['name']} [{rule['severity']}]")
        return True
    except config_client.exceptions.MaxNumberOfConfigRulesExceededException:
        print(f"  ✗ Limit reached — cannot create {rule['name']}")
        return False
    except Exception as e:
        print(f"  ✗ Failed to create {rule['name']}: {e}")
        return False


def verify_rules():
    print("\n--- Verifying rules in AWS ---")
    response = config_client.describe_config_rules()
    rules = response.get("ConfigRules", [])
    print(f"Total rules active: {len(rules)}\n")
    for rule in rules:
        name = rule["ConfigRuleName"]
        state = rule.get("ConfigRuleState", "UNKNOWN")
        print(f"  • {name}  [{state}]")


def main():
    print("=== Setting up AWS Config Security Rules ===\n")
    created = 0
    for rule in RULES:
        if create_rule(rule):
            created += 1
    print(f"\n{created}/{len(RULES)} rules created successfully.")
    verify_rules()
    print("\nDone. Rules are now evaluating your AWS resources.")


if __name__ == "__main__":
    main()