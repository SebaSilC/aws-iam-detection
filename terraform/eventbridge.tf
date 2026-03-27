resource "aws_cloudwatch_event_rule" "iam_events" {
  name = "${local.prefix}-iam-events"

  event_pattern = jsonencode({
    source = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AttachRolePolicy",
        "PutUserPolicy",
        "CreatePolicyVersion",
        "PassRole"
      ]
    }
  })
}
