import sys
import os
import json
from datetime import datetime

# Add paths
sys.path.append(os.path.join(os.path.dirname(__file__), 'threat-detector'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'alert-system'))

from detector import get_cloudtrail_logs
from alerter import send_alert

def run_security_scan():
    print("=" * 60)
    print("   CLOUD SECURITY THREAT DETECTION PLATFORM")
    print(f"   Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Step 1: Scan for threats
    threats = get_cloudtrail_logs()

    # Step 2: Alert for each threat found
    if threats:
        print(f"\n🚨 {len(threats)} threat(s) found! Sending alerts...")
        for threat in threats:
            send_alert(threat)
    else:
        print("\n✅ System secure — No threats detected.")

    print("\n" + "=" * 60)
    print(f"   Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

if __name__ == "__main__":
    run_security_scan()