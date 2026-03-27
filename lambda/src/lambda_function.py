import json
import boto3
import os
from datetime import datetime

sns = boto3.client('sns')
s3 = boto3.client('s3')
iam = boto3.client('iam')

SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
S3_BUCKET = os.environ["S3_BUCKET"]

def lambda_handler(event, context):
    detail = event.get("detail", {})

    event_name = detail.get("eventName")
    user = detail.get("userIdentity", {}).get("arn", "unknown")
    source_ip = detail.get("sourceIPAddress")
    request = detail.get("requestParameters", {})

    risk = "LOW"
    reason = "No issue detected"

    # --- Detection Logic (High-impact upgrade) ---

    # 1. Policy version escalation
    if event_name == "CreatePolicyVersion":
        if request.get("setAsDefault") is True:
            risk = "CRITICAL"
            reason = "Policy version set as default (privilege escalation)"

    # 2. PassRole abuse
    if event_name == "PassRole":
        role_arn = request.get("roleArn", "")
        if "Admin" in role_arn or "Power" in role_arn:
            risk = "HIGH"
            reason = "Suspicious PassRole usage"

    # 3. Inline policy creation
    if event_name == "PutUserPolicy":
        risk = "HIGH"
        reason = "Inline policy attached to user"

    target = request.get("roleName") or request.get("userName") or "unknown"

    finding = {
        "time": detail.get("eventTime"),
        "actor": user,
        "action": event_name,
        "target": target,
        "source_ip": source_ip,
        "risk": risk,
        "reason": reason
    }

    # --- Store in S3 ---
    s3.put_object(
        Bucket=S3_BUCKET,
        Key=f"findings/{datetime.utcnow().isoformat()}.json",
        Body=json.dumps(finding)
    )

    # --- Alert ---
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="IAM Security Alert",
        Message=json.dumps(finding, indent=2)
    )

    return finding
