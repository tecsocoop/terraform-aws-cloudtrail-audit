variable "name" {
  description = "Prefix used to name the SNS topic and EventBridge rules. Example: security-audit"
  type        = string

  validation {
    condition     = can(regex("^[0-9A-Za-z._-]+$", var.name)) && length(var.name) >= 1 && length(var.name) <= 40
    error_message = "name must contain only letters, numbers, periods, underscores, or hyphens and must be between 1 and 40 characters."
  }
}

variable "notification_email" {
  description = "Email address that receives CloudTrail audit notifications. The SNS subscription must be confirmed by email."
  type        = string

  validation {
    condition     = can(regex("^[^[:space:]@]+@[^[:space:]@]+\\.[^[:space:]@]+$", var.notification_email))
    error_message = "notification_email must be a valid email address."
  }
}

variable "exception_role_arns" {
  description = "IAM role ARNs excluded from Secrets Manager GetSecretValue and BatchGetSecretValue email alerts."
  type        = set(string)
  default     = []
}

variable "enable_iam_events" {
  description = "Enable IAM audit events. The AWS provider must use us-east-1 when enabled."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags applied to all resources created by the module."
  type        = map(string)
  default     = {}
}
