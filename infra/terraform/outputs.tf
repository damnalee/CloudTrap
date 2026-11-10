output "raw_logs_bucket" {
  description = "Private S3 bucket receiving Cowrie JSON logs."
  value       = aws_s3_bucket.raw_logs.bucket
}

output "ingest_queue_url" {
  value = aws_sqs_queue.ingest.url
}

output "ingest_lambda_name" {
  value = aws_lambda_function.ingest.function_name
}

output "events_table_name" {
  value = aws_dynamodb_table.events.name
}

output "alerts_table_name" {
  value = aws_dynamodb_table.alerts.name
}

output "incidents_table_name" {
  value = aws_dynamodb_table.incidents.name
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "cloudwatch_dashboard_url" {
  value = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=CloudTrap-Security"
}
