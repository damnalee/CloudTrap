variable "aws_region" {
  description = "AWS region for CloudTrap resources."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment tag applied to CloudTrap resources."
  type        = string
  default     = "production"
}

variable "raw_log_retention_days" {
  description = "Retention period for raw Cowrie JSON objects in S3."
  type        = number
  default     = 30
  validation {
    condition     = var.raw_log_retention_days >= 1 && var.raw_log_retention_days <= 365
    error_message = "Raw log retention must be between 1 and 365 days."
  }
}

variable "lambda_timeout_seconds" {
  description = "Lambda execution timeout. SQS visibility timeout is six times this value."
  type        = number
  default     = 60
  validation {
    condition     = var.lambda_timeout_seconds >= 10 && var.lambda_timeout_seconds <= 900
    error_message = "Lambda timeout must be between 10 and 900 seconds."
  }
}

variable "lambda_memory_size" {
  description = "Memory allocated to the ingestion Lambda."
  type        = number
  default     = 256
  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "Lambda memory must be between 128 and 10240 MB."
  }
}

variable "alert_email" {
  description = "Optional SNS email notification address. It must confirm the subscription."
  type        = string
  default     = ""
  validation {
    condition     = var.alert_email == "" || can(regex("^[^@ ]+@[^@ ]+\\.[^@ ]+$", var.alert_email))
    error_message = "alert_email must be empty or a valid email address."
  }
}
