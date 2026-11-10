terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.72.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "CloudTrap"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  name          = "cloudtrap"
  bucket_name   = "${local.name}-raw-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
  queue_name    = "${local.name}-ingest"
  dlq_name      = "${local.name}-ingest-dlq"
  function_name = "${local.name}-ingest"
}

resource "aws_s3_bucket" "raw_logs" {
  bucket        = local.bucket_name
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "raw_logs" {
  bucket                  = aws_s3_bucket.raw_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "raw_logs" {
  bucket = aws_s3_bucket.raw_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "raw_logs" {
  bucket = aws_s3_bucket.raw_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "raw_logs" {
  bucket = aws_s3_bucket.raw_logs.id
  rule {
    id     = "expire-raw-honeypot-logs"
    status = "Enabled"
    filter {
      prefix = "cowrie/"
    }
    expiration {
      days = var.raw_log_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

resource "aws_sqs_queue" "dlq" {
  name                      = local.dlq_name
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "ingest" {
  name                       = local.queue_name
  visibility_timeout_seconds = var.lambda_timeout_seconds * 6
  message_retention_seconds  = 345600
  receive_wait_time_seconds  = 20
  sqs_managed_sse_enabled    = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 3
  })
}

resource "aws_sqs_queue_policy" "allow_s3" {
  queue_url = aws_sqs_queue.ingest.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowOnlyCloudTrapBucketNotifications"
      Effect = "Allow"
      Principal = {
        Service = "s3.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.ingest.arn
      Condition = {
        ArnLike = {
          "aws:SourceArn" = aws_s3_bucket.raw_logs.arn
        }
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_dynamodb_table" "events" {
  name         = "CloudTrapEvents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "event_id"

  attribute {
    name = "event_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
  server_side_encryption {
    enabled = true
  }
}

resource "aws_dynamodb_table" "alerts" {
  name         = "CloudTrapAlerts"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "alert_id"

  attribute {
    name = "alert_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
  server_side_encryption {
    enabled = true
  }
}

resource "aws_dynamodb_table" "incidents" {
  name         = "CloudTrapIncidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
  server_side_encryption {
    enabled = true
  }
}

resource "aws_sns_topic" "alerts" {
  name = "cloudtrap-threat-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  for_each  = var.alert_email == "" ? toset([]) : toset([var.alert_email])
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

resource "aws_iam_role" "lambda" {
  name = "CloudTrapIngestLambdaRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 14
}

resource "aws_iam_role_policy" "lambda" {
  name = "CloudTrapIngestPermissions"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadRawLogs"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["${aws_s3_bucket.raw_logs.arn}/*"]
      },
      {
        Sid    = "ConsumeIngestQueue"
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = [aws_sqs_queue.ingest.arn]
      },
      {
        Sid    = "WriteCloudTrapRecords"
        Effect = "Allow"
        Action = ["dynamodb:PutItem"]
        Resource = [
          aws_dynamodb_table.events.arn,
          aws_dynamodb_table.alerts.arn,
          aws_dynamodb_table.incidents.arn
        ]
      },
      {
        Sid      = "PublishThreatNotifications"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.alerts.arn]
      },
      {
        Sid      = "PublishCloudTrapMetrics"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "CloudTrap"
          }
        }
      },
      {
        Sid    = "WriteLambdaLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
      }
    ]
  })
}

resource "aws_lambda_function" "ingest" {
  function_name = local.function_name
  role          = aws_iam_role.lambda.arn
  runtime       = "python3.13"
  handler       = "lambda_function.lambda_handler"

  filename         = "${path.module}/build/cloudtrap-ingest.zip"
  source_code_hash = filebase64sha256("${path.module}/build/cloudtrap-ingest.zip")

  timeout                        = var.lambda_timeout_seconds
  memory_size                    = var.lambda_memory_size
  reserved_concurrent_executions = 2
  architectures                  = ["arm64"]

  environment {
    variables = {
      RAW_BUCKET_NAME  = aws_s3_bucket.raw_logs.bucket
      EVENTS_TABLE     = aws_dynamodb_table.events.name
      ALERTS_TABLE     = aws_dynamodb_table.alerts.name
      INCIDENTS_TABLE  = aws_dynamodb_table.incidents.name
      ALERTS_TOPIC_ARN = aws_sns_topic.alerts.arn
      MAX_OBJECT_BYTES = "26214400"
    }
  }

  depends_on = [
    aws_iam_role_policy.lambda,
    aws_cloudwatch_log_group.lambda
  ]
}

resource "aws_lambda_event_source_mapping" "sqs" {
  event_source_arn        = aws_sqs_queue.ingest.arn
  function_name           = aws_lambda_function.ingest.arn
  batch_size              = 5
  enabled                 = true
  function_response_types = ["ReportBatchItemFailures"]

  scaling_config {
    maximum_concurrency = 2
  }
}

resource "aws_s3_bucket_notification" "raw_logs" {
  bucket = aws_s3_bucket.raw_logs.id
  queue {
    queue_arn     = aws_sqs_queue.ingest.arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = "cowrie/"
    filter_suffix = ".json"
  }
  depends_on = [aws_sqs_queue_policy.allow_s3]
}

resource "aws_cloudwatch_metric_alarm" "high_severity_alerts" {
  alarm_name          = "CloudTrap-HighSeverityAlerts"
  alarm_description   = "One or more high or critical CloudTrap alerts were detected."
  namespace           = "CloudTrap"
  metric_name         = "HighSeverityAlerts"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "CloudTrap-Security"
  dashboard_body = jsonencode({
    widgets = [{
      type   = "metric"
      x      = 0
      y      = 0
      width  = 12
      height = 6
      properties = {
        title  = "CloudTrap ingestion and detections"
        view   = "timeSeries"
        region = var.aws_region
        period = 300
        stat   = "Sum"
        metrics = [
          ["CloudTrap", "EventsProcessed"],
          ["CloudTrap", "AlertsGenerated"],
          ["CloudTrap", "HighSeverityAlerts"],
          ["CloudTrap", "IncidentsGenerated"]
        ]
      }
    }]
  })
}
