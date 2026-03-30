import json
import boto3
import os
from datetime import datetime

sns = boto3.client('sns')
s3 = boto3.client('s3')
iam = boto3.client('iam')

# Environment configuration
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
S3_BUCKET = os.environ["S3_BUCKET"]
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")
PROJECT_NAME = os.environ.get("PROJECT_NAME", "iam-detection")

# Detection tuning (not hardcoded, but controlled)
PRIVILEGED_ROLE_KEYWORDS = os.environ.get(
    "PRIVILEGED_ROLE_KEYWORDS", "Admin,Power,FullAccess"
).split(",")

FINDINGS_PREFIX = os.environ.get("FINDINGS_PREFIX", "iam-findings")

def lambda_handler(event, context):
    detail = event.get("detail", {})

    event_name = detail.get("eventName")
    user = detail.get("userIdentity", {}).get("arn", "unknown")
    source_ip = detail.get("sourceIPAddress")
    request = detail.get("requestParameters", {})

    risk = "LOW"
    reason = "No suspicious behavior detected"

    # --- Detection Logic ---

    # 1. Policy version escalation
    if event_name == "CreatePolicyVersion":
        if request.get("setAsDefault") is True:
            risk = "CRITICAL"
            reason = "New policy version set as default (potential privilege escalation)"

    # 2. PassRole abuse (keyword-based detection)
    if event_name == "PassRole":
        role_arn = request.get("roleArn", "")
        if any(keyword in role_arn for keyword in PRIVILEGED_ROLE_KEYWORDS):
            risk = "HIGH"
            reason = "PassRole used with privileged role pattern"

    # 3. Inline policy injection
    if event_name == "PutUserPolicy":
        risk = "HIGH"
        reason = "Inline policy attached to IAM user"

    target = (
        request.get("roleName")
        or request.get("userName")
        or request.get("groupName")
        or "unknown"
    )

    timestamp = detail.get("eventTime")

    finding = {
        "project": PROJECT_NAME,
        "environment": ENVIRONMENT,
        "time": timestamp,
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
        Key=f"{FINDINGS_PREFIX}/{ENVIRONMENT}/{datetime.utcnow().isoformat()}.json",
        Body=json.dumps(finding)
    )

    # --- Alert ---
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[{ENVIRONMENT}] IAM Security Alert - {risk}",
        Message=json.dumps(finding, indent=2)
    )

    return finding
