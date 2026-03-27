# AWS IAM Detection & Response Lab

## Overview

This project demonstrates how I built an **AWS-native detection and response pipeline** to identify and analyze high-risk IAM activity in real time.

The goal was to simulate a realistic cloud security workflow where raw audit logs are not just collected, but **processed, enriched, and turned into actionable findings**.

This project focuses specifically on detecting **potential IAM privilege escalation patterns**, which are a common risk in AWS environments.

---

## Problem It Solves

CloudTrail logs provide detailed visibility into AWS activity, but:

- They generate **high volumes of raw, low-context data**
- Alerts based only on API calls are often **noisy and difficult to investigate**
- There is no built-in mechanism to **analyze intent or risk level**

This project addresses that gap by introducing:

- **Event-driven processing**
- **Context enrichment**
- **Basic security analysis**
- **Structured alerting**

---

## Architecture

CloudTrail → EventBridge → Lambda → SNS
→ S3 (findings)
→ CloudWatch Logs

---

## How It Works

1. **CloudTrail**
   - Captures IAM API activity across the account

2. **EventBridge**
   - Filters high-risk IAM actions (e.g. policy changes, role usage)

3. **Lambda (boto3)**
   - Parses incoming events
   - Extracts key context (actor, action, resource, IP)
   - Applies detection logic for privilege escalation patterns
   - Assigns risk level and reasoning

4. **SNS**
   - Sends enriched alerts instead of raw logs

5. **S3**
   - Stores structured findings for later investigation

6. **AWS Config & GuardDuty**
   - Provide additional governance and threat detection signals

---

## Key Features

### Detection
Monitors high-risk IAM API calls such as:

- `AttachRolePolicy`
- `PutUserPolicy`
- `CreatePolicyVersion`
- `PassRole`

---

### Analysis (Privilege Escalation Patterns)

Implements basic detection logic for common escalation techniques:

- **Policy version takeover**
  - Creating a new policy version and setting it as default

- **PassRole abuse**
  - Passing high-privilege roles to services

- **Inline policy injection**
  - Attaching policies directly to users

---

### Enrichment

Transforms raw CloudTrail events into structured findings by extracting:

- Actor (IAM identity)
- Action performed
- Target resource
- Source IP address
- Risk level
- Reason for detection

---

### Response (Safe Automation)

- Sends enriched alerts via SNS  
- Stores findings in S3  
- Logs events in CloudWatch  

No destructive actions are taken to keep the system safe and predictable.

---

## Example Finding

```json
{
  "time": "2026-03-27T10:00:00Z",
  "actor": "arn:aws:iam::123456789012:user/admin",
  "action": "CreatePolicyVersion",
  "target": "AdminPolicy",
  "source_ip": "1.2.3.4",
  "risk": "CRITICAL",
  "reason": "Policy version set as default (privilege escalation)"
}
```
--

## Deployment

### Terraform

```bash
cd terraform
terraform init
terraform apply
```

Lambda Packaging
```cd lambda
chmod +x build.sh
./build.sh
```

--

## Security Considerations

- IAM roles follow **least privilege principles**
- Access to SNS and S3 is **scoped to specific resources**
- No sensitive values are hardcoded
- Automation is **non-destructive by design**

---

## What I Learned

- How to build **event-driven pipelines in AWS**
- How to process and analyze **CloudTrail logs programmatically**
- How IAM misconfigurations can lead to **privilege escalation risks**
- How to design systems that balance **detection and safe response**

---

## Future Improvements

- Integrate with **AWS Security Hub**
- Add **IP reputation / GeoIP enrichment**
- Expand detection logic for additional IAM attack paths
- Introduce **controlled remediation workflows**

