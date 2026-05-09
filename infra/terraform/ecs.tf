resource "aws_ecs_cluster" "this" {
  name = "${var.project_name}-${var.environment}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = aws_ecs_cluster.this.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = "${var.project_name}-backend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = "backend"
      image     = "${aws_ecr_repository.this.repository_url}:latest"
      essential = true

      portMappings = [
        {
          containerPort = var.container_port
          protocol      = "tcp"
        }
      ]

      # Non-sensitive config injected as plain env vars
      environment = [
        { name = "NODE_ENV",             value = "production" },
        { name = "PORT",                 value = tostring(var.container_port) },
        { name = "TOKEN_EXPIRY",         value = var.token_expiry },
        { name = "ALLOWED_ORIGINS",      value = var.allowed_origins },
        { name = "FROM_EMAIL",           value = var.from_email },
        { name = "CVAT_API_URL",         value = var.cvat_api_url },
        { name = "CVAT_PUBLIC_URL",      value = var.cvat_public_url },
        { name = "CONTACT_NOTIFY_EMAIL", value = var.contact_notify_email },
      ]

      # Sensitive values pulled from Secrets Manager at task start — never in plaintext
      secrets = [
        {
          name      = "ADMIN_SECRET_KEY"
          valueFrom = aws_secretsmanager_secret.admin_secret_key.arn
        },
        {
          name      = "AUTH_TOKEN_SECRET"
          valueFrom = aws_secretsmanager_secret.auth_token_secret.arn
        },
        {
          name      = "MONGODB_URI"
          valueFrom = aws_secretsmanager_secret.mongodb_uri.arn
        },
        {
          name      = "RESEND_API_KEY"
          valueFrom = aws_secretsmanager_secret.resend_api_key.arn
        },
        {
          name      = "CVAT_INTERNAL_API_KEY"
          valueFrom = aws_secretsmanager_secret.cvat_internal_api_key.arn
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "wget -qO- http://localhost:${var.container_port}/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }

      user = "1001"
    }
  ])

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_ecs_service" "this" {
  name            = "${var.project_name}-backend"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = "backend"
    container_port   = var.container_port
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_controller {
    type = "ECS"
  }

  health_check_grace_period_seconds = 60

  depends_on = [
    aws_lb_listener.http_forward,
    aws_lb_listener.http_redirect,
    aws_lb_listener.https,
  ]

  lifecycle {
    # CI/CD manages task_definition; Auto Scaling manages desired_count
    ignore_changes = [task_definition, desired_count]
  }
}
