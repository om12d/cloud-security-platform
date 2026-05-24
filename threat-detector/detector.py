import boto3
import json
import gzip
import os
from datetime import datetime

# AWS Configuration
BUCKET_NAME = "cloud-security-logs-347152106261"
REGION = "us-east-1"

# Suspicious events to watch for
THREAT_EVENTS = [
    "ConsoleLogin",
    "DeleteTrail",
    "StopLogging",
    "DeleteBucket",
    "PutBucketPolicy",
    "CreateAccessKey",
    "AttachUserPolicy",
    "AuthorizeSecurityGroupIngress",
    "DescribeInstances"
]

def get_cloudtrail_logs():
    """Fetch CloudTrail logs from S3"""
    s3 = boto3.client("s3", region_name=REGION)
    threats_found = []

    print("🔍 Scanning CloudTrail logs for threats...")
    print(f"📦 Bucket: {BUCKET_NAME}")
    print("-" * 50)

    try:
        response = s3.list_objects_v2(Bucket=BUCKET_NAME)

        if "Contents" not in response:
            print("⚠️  No logs found yet. CloudTrail may still be collecting.")
            return []

        for obj in response["Contents"]:
            key = obj["Key"]
            if not key.endswith(".json.gz"):
                continue

            # Download and read the log file
            log_obj = s3.get_object(Bucket=BUCKET_NAME, Key=key)
            compressed = log_obj["Body"].read()
            log_data = json.loads(gzip.decompress(compressed))

            # Analyze each event
            for event in log_data.get("Records", []):
                event_name = event.get("eventName", "")
                user = event.get("userIdentity", {}).get("arn", "Unknown")
                source_ip = event.get("sourceIPAddress", "Unknown")
                event_time = event.get("eventTime", "Unknown")
                error = event.get("errorCode", None)

                # Flag suspicious events
                if event_name in THREAT_EVENTS or error:
                    threat = {
                        "event": event_name,
                        "user": user,
                        "source_ip": source_ip,
                        "time": event_time,
                        "error": error or "None"
                    }
                    threats_found.append(threat)
                    print(f"🚨 THREAT DETECTED!")
                    print(f"   Event    : {event_name}")
                    print(f"   User     : {user}")
                    print(f"   IP       : {source_ip}")
                    print(f"   Time     : {event_time}")
                    print(f"   Error    : {error or 'None'}")
                    print("-" * 50)

    except Exception as e:
        print(f"❌ Error: {str(e)}")

    return threats_found


def save_report(threats):
    """Save threat report to logs folder"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join("..", "logs", f"threat_report_{timestamp}.json")

    with open(report_path, "w") as f:
        json.dump(threats, f, indent=2)

    print(f"\n✅ Report saved: {report_path}")
    print(f"📊 Total threats found: {len(threats)}")


if __name__ == "__main__":
    threats = get_cloudtrail_logs()
    if threats:
        save_report(threats)
    else:
        print("\n✅ No threats detected at this time.")