import boto3
import json

iam_client = boto3.client('iam')
sns_client = boto3.client('sns', region_name='us-east-1')

SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:347152106261:cloud-security-alerts"

DANGEROUS_ACTIONS = [
    "*",
    "iam:*",
    "s3:*",
    "ec2:*",
    "lambda:*"
]

findings = []


def flag(severity, resource, issue, recommendation):
    finding = {
        "severity": severity,
        "resource": resource,
        "issue": issue,
        "recommendation": recommendation
    }
    findings.append(finding)
    print(f"  ⚠ [{severity}] {resource}")
    print(f"      Issue: {issue}")
    print(f"      Fix:   {recommendation}\n")


def check_users():
    print("--- Checking IAM users ---")
    users = iam_client.list_users().get("Users", [])
    print(f"  Found {len(users)} users\n")

    for user in users:
        username = user["UserName"]

        # Check MFA
        mfa_devices = iam_client.list_mfa_devices(UserName=username).get("MFADevices", [])
        if not mfa_devices:
            flag(
                severity="CRITICAL",
                resource=f"IAM User: {username}",
                issue="No MFA device enabled",
                recommendation="Enable MFA immediately — go to IAM → Users → Security credentials"
            )

        # Check for admin access
        attached = iam_client.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
        for policy in attached:
            if "Administrator" in policy["PolicyName"]:
                flag(
                    severity="HIGH",
                    resource=f"IAM User: {username}",
                    issue=f"Has AdministratorAccess policy attached",
                    recommendation="Use least-privilege — only grant permissions actually needed"
                )

        # Check inline policies for wildcard actions
        inline_policies = iam_client.list_user_policies(UserName=username).get("PolicyNames", [])
        for policy_name in inline_policies:
            doc = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)
            policy_doc = doc["PolicyDocument"]
            for statement in policy_doc.get("Statement", []):
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                for action in actions:
                    if action in DANGEROUS_ACTIONS:
                        flag(
                            severity="CRITICAL",
                            resource=f"IAM User: {username} / Policy: {policy_name}",
                            issue=f"Inline policy contains dangerous action: {action}",
                            recommendation="Replace wildcard actions with specific permissions"
                        )


def check_roles():
    print("--- Checking IAM roles ---")
    roles = iam_client.list_roles().get("Roles", [])
    print(f"  Found {len(roles)} roles\n")

    for role in roles:
        role_name = role["RoleName"]

        attached = iam_client.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
        for policy in attached:
            if "Administrator" in policy["PolicyName"]:
                flag(
                    severity="HIGH",
                    resource=f"IAM Role: {role_name}",
                    issue="Role has AdministratorAccess attached",
                    recommendation="Scope down permissions to only what this role needs"
                )


def send_summary_alert():
    if not findings:
        return

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]

    message = f"""IAM SECURITY ANALYSIS REPORT
=============================
Total findings: {len(findings)}
CRITICAL: {len(critical)}
HIGH:     {len(high)}

--- FINDINGS ---
"""
    for f in findings:
        message += f"\n[{f['severity']}] {f['resource']}\n"
        message += f"  Issue: {f['issue']}\n"
        message += f"  Fix:   {f['recommendation']}\n"

    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"IAM Security Report: {len(findings)} findings ({len(critical)} CRITICAL)",
        Message=message
    )
    print(f"  ✓ Summary alert sent to email")


def main():
    print("=== IAM Security Analyzer ===\n")

    check_users()
    check_roles()

    print(f"--- Summary ---")
    print(f"Total findings: {len(findings)}")

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    print(f"CRITICAL: {len(critical)}")
    print(f"HIGH:     {len(high)}")

    if findings:
        print("\nSending summary alert email...")
        send_summary_alert()
    else:
        print("\n✓ No IAM issues found — all clean!")

    print("\nDone.")


if __name__ == "__main__":
    main()