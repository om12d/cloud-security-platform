import boto3
import json
from datetime import datetime

# SNS Configuration
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:347152106261:cloud-security-alerts"
REGION = "us-east-1"

def send_alert(threat):
    """Send email alert via AWS SNS"""
    sns = boto3.client("sns", region_name=REGION)

    subject = f"🚨 SECURITY ALERT: {threat['event']} Detected"

    message = f"""
CLOUD SECURITY THREAT DETECTED
================================
Time      : {threat['time']}
Event     : {threat['event']}
User      : {threat['user']}
Source IP : {threat['source_ip']}
Error     : {threat['error']}
================================
Immediate action may be required.
Cloud Security Platform - Auto Alert
    """

    try:
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=subject
        )
        print(f"✅ Alert sent! Message ID: {response['MessageId']}")
        return True
    except Exception as e:
        print(f"❌ Failed to send alert: {str(e)}")
        return False


def send_test_alert():
    """Send a test alert to verify everything works"""
    test_threat = {
        "event": "TEST_ALERT",
        "user": "arn:aws:iam::347152106261:user/security-admin",
        "source_ip": "192.168.1.1",
        "time": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "error": "None"
    }
    print("📧 Sending test alert to your email...")
    send_alert(test_threat)


if __name__ == "__main__":
    send_test_alert()