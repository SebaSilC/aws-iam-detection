resource "aws_lambda_function" "detector" {
  function_name = "${local.prefix}-lambda"

  role    = aws_iam_role.lambda_role.arn
  handler = "lambda_function.lambda_handler"
  runtime = "python3.11"

  filename = "../lambda/lambda.zip"

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
      S3_BUCKET     = aws_s3_bucket.findings.bucket
    }
  }
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule = aws_cloudwatch_event_rule.iam_events.name
  arn  = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_events.arn
}
