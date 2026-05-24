# Cloud Security Threat Detection Platform

A real-time cloud security monitoring system built on AWS that automatically detects threats, analyzes CloudTrail logs, and sends instant alerts.

## Architecture
- **AWS CloudTrail** — Monitors and records all AWS account activity
- **AWS S3** — Stores CloudTrail logs securely
- **Python Detector** — Analyzes logs and flags suspicious events
- **AWS SNS** — Sends real-time email alerts when threats are detected

## Features
- Real-time threat detection from CloudTrail logs
- Automated email alerting via AWS SNS
- Detects: unauthorized access, IAM changes, suspicious API calls
- Generates JSON threat reports with timestamps

## Project Structure
cloud-security-platform/
├── threat-detector/
│   └── detector.py       # Core threat detection engine
├── alert-system/
│   └── alerter.py        # AWS SNS alerting system
├── main.py               # Main orchestration engine
└── logs/                 # Generated threat reports
## Setup
```bash
pip install boto3
aws configure
python main.py
```

## Tech Stack
Python · AWS CloudTrail · AWS S3 · AWS SNS · boto3 · IAM