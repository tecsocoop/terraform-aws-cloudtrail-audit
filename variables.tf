variable "name" {
  description = "Prefix used to name all resources created by the module. Example: security-audit"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.name)) && length(var.name) >= 3 && length(var.name) <= 40
    error_message = "name must contain only lowercase letters, numbers, or hyphens; start and end with a letter or number; and be between 3 and 40 characters."
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

variable "tags" {
  description = "Additional tags applied to all resources created by the module."
  type        = map(string)
  default     = {}
}
