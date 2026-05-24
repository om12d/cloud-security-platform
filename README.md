# Cloud Security Hardening & Auto-Remediation Platform

A production-grade AWS cloud security platform that detects threats, automatically remediates violations, analyzes IAM policies, and generates CIS Benchmark compliance reports.

## Platform Capabilities

| Module | Description | Tech |
|---|---|---|
| Threat Detection | Scans CloudTrail logs, flags suspicious events | Python, AWS S3, CloudTrail |
| Auto-Remediation | Automatically fixes S3 and SSH violations | Python, AWS Lambda, SNS |
| IAM Analyzer | Scans all IAM users and roles for overpermissive access | Python, AWS IAM |
| Config Rules | 6 CIS security rules continuously monitoring AWS resources | AWS Config |
| Compliance Report | Generates PDF CIS Benchmark report with live AWS data | Python, ReportLab |

## Results

- Detected 11 live threats on first scan (Project 1)
- Auto-remediated S3 public access violation in real time
- Found 2 IAM security findings (1 CRITICAL) on live account
- CIS Benchmark Score: 87% (7/8 checks passed)
- 6 AWS Config rules actively monitoring account 24/7

## Project Structure
cloud-security-platform/
├── threat-detector/        # CloudTrail log scanner
├── alert-system/           # AWS SNS email alerting
├── config-rules/           # AWS Config security rules
├── lambda-remediation/     # Auto-fix engine
├── iam-analyzer/           # IAM policy scanner
├── compliance-report/      # CIS Benchmark PDF generator
└── main.py                 # Main orchestrator
## Tech Stack

Python · AWS CloudTrail · AWS Config · AWS Lambda · AWS IAM · AWS SNS · AWS S3 · boto3 · ReportLab · GitHub Actions

## Setup

```bash
git clone https://github.com/om12d/cloud-security-platform
cd cloud-security-platform
py -m pip install boto3 reportlab
aws configure
py main.py
```

## Security Checks Covered

- S3 public access blocking
- SSH unrestricted access (0.0.0.0/0)
- IAM MFA enforcement
- Root account MFA
- CloudTrail logging
- EBS volume encryption
- Auto-remediation with real-time alerts