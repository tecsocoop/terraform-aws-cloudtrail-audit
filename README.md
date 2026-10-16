# terraform-aws-cloudtrail-audit

Terraform module that sends email notifications for security-sensitive AWS API
activity recorded by CloudTrail. It creates EventBridge rules, an SNS topic and
an email subscription.

## Requirements

| Name      | Version  |
|-----------|----------|
| terraform | >= 1.3.7 |
| aws       | >= 6.0.0 |

An enabled CloudTrail trail that records management events is required.

## How it works

The module creates EventBridge rules that match CloudTrail events and sends the
matched event details to an SNS email subscription.

It monitors:

- IAM users, groups, roles, policies, MFA devices and login profiles.
- Access key creation, status changes and deletion.
- Secrets Manager secret, value, policy, rotation and replication changes.
- Secrets Manager `GetSecretValue` and `BatchGetSecretValue` operations.

Roles listed in `exception_role_arns` do not generate notifications for secret
read operations. IAM and Secrets Manager modification events are not excluded.

## Region configuration

The module inherits the AWS provider configured by the project that consumes
it. Secrets Manager events are monitored in that provider region.

IAM is a global service and its CloudTrail events are delivered to EventBridge
in `us-east-1`. The IAM rule is enabled automatically when the inherited
provider uses `us-east-1` and disabled in other regions.

## Usage

```hcl
module "cloudtrail_audit" {
  source  = "tecsocoop/cloudtrail-audit/aws"
#  version = "X.X.X" # see the latest available tag

  name               = "security-audit"
  notification_email = "security@example.com"

#  exception_role_arns = [
#    "arn:aws:iam::123456789012:role/external-secrets-operator",
#  ]

  tags = {
    Environment = "production"
  }
}
```

AWS sends a confirmation message to `notification_email` after the first
apply. The recipient must confirm the SNS subscription before notifications
can be delivered.

## Variables

| Variable | Descripción | Valores | Default |
|----------|-------------|---------|---------|
| `name` | Prefix used for SNS and EventBridge resource names. | string, 1-40 characters | - |
| `notification_email` | Email address that receives audit notifications. | valid email address | - |
| `exception_role_arns` | IAM roles excluded from Secrets Manager read notifications. | `set(string)` of IAM role ARNs | `[]` |
| `tags` | Additional tags applied to module resources. | `map(string)` | `{}` |

## Outputs

| Output | Description |
|--------|-------------|
| `sns_topic_arn` | ARN of the SNS notification topic. |
| `email_subscription_arn` | ARN of the email subscription. |
| `event_rule_arns` | EventBridge rule ARNs keyed by audit category. |
| `event_rule_names` | EventBridge rule names keyed by audit category. |

## References

- CloudTrail events in EventBridge: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail.html
- IAM activity in CloudTrail: https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html
- Secrets Manager activity in CloudTrail: https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-cloudtrail.html
- SNS email subscriptions: https://docs.aws.amazon.com/sns/latest/dg/sns-email-notifications.html
- Terraform provider configuration: https://developer.hashicorp.com/terraform/language/modules/develop/providers

## License

Licensed under the [Apache License 2.0](LICENSE).
