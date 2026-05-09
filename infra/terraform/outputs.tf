output "alb_dns_name" {
  description = "Public DNS of the Application Load Balancer — point your CNAME here"
  value       = aws_lb.this.dns_name
}

output "ecr_repository_url" {
  description = "Full ECR URL used in docker push / task definition"
  value       = aws_ecr_repository.this.repository_url
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "ecs_service_name" {
  value = aws_ecs_service.this.name
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.ecs.name
}

output "secret_arns" {
  description = "Populate these secrets before the first deployment"
  value = {
    ADMIN_SECRET_KEY      = aws_secretsmanager_secret.admin_secret_key.arn
    AUTH_TOKEN_SECRET     = aws_secretsmanager_secret.auth_token_secret.arn
    MONGODB_URI           = aws_secretsmanager_secret.mongodb_uri.arn
    RESEND_API_KEY        = aws_secretsmanager_secret.resend_api_key.arn
    CVAT_INTERNAL_API_KEY = aws_secretsmanager_secret.cvat_internal_api_key.arn
  }
}
