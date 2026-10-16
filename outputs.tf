output "cloudtrail_name" {
  description = "Name of the multi-Region CloudTrail trail."
  value       = aws_cloudtrail.audit.name
}

output "cloudtrail_arn" {
  description = "ARN of the multi-Region CloudTrail trail."
  value       = aws_cloudtrail.audit.arn
}

output "cloudtrail_s3_bucket_id" {
  description = "ID of the S3 bucket that stores CloudTrail log files."
  value       = aws_s3_bucket.cloudtrail.id
}

output "cloudtrail_s3_bucket_arn" {
  description = "ARN of the S3 bucket that stores CloudTrail log files."
  value       = aws_s3_bucket.cloudtrail.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic that delivers audit notifications."
  value       = aws_sns_topic.audit.arn
}

output "email_subscription_arn" {
  description = "ARN of the email subscription. The value remains pending confirmation until the recipient confirms it."
  value       = aws_sns_topic_subscription.email.arn
}

output "event_rule_arns" {
  description = "Map of EventBridge audit rule names to ARNs."
  value = {
    iam_changes               = aws_cloudwatch_event_rule.iam_changes.arn
    secret_changes            = aws_cloudwatch_event_rule.secret_changes.arn
    secret_reads_direct       = aws_cloudwatch_event_rule.secret_reads_direct.arn
    secret_reads_assumed_role = aws_cloudwatch_event_rule.secret_reads_assumed_role.arn
  }
}

output "event_rule_names" {
  description = "Map of EventBridge audit rule names keyed by audit category."
  value = {
    iam_changes               = aws_cloudwatch_event_rule.iam_changes.name
    secret_changes            = aws_cloudwatch_event_rule.secret_changes.name
    secret_reads_direct       = aws_cloudwatch_event_rule.secret_reads_direct.name
    secret_reads_assumed_role = aws_cloudwatch_event_rule.secret_reads_assumed_role.name
  }
}
