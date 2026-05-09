data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# ── Execution role ─────────────────────────────────────────────────────────────
# Used by the ECS agent (not the app) to pull the image from ECR and inject secrets.

resource "aws_iam_role" "execution" {
  name               = "${var.project_name}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  name = "read-app-secrets"
  role = aws_iam_role.execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = [
          aws_secretsmanager_secret.admin_secret_key.arn,
          aws_secretsmanager_secret.auth_token_secret.arn,
          aws_secretsmanager_secret.mongodb_uri.arn,
          aws_secretsmanager_secret.resend_api_key.arn,
          aws_secretsmanager_secret.cvat_internal_api_key.arn,
        ]
      }
    ]
  })
}

# ── Task role ──────────────────────────────────────────────────────────────────
# Credentials the running application code can assume. Follows least-privilege:
# only CloudWatch Logs writes are needed at runtime.

resource "aws_iam_role" "task" {
  name               = "${var.project_name}-ecs-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy" "task_logs" {
  name = "cloudwatch-log-writes"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.ecs.arn}:*"
      }
    ]
  })
}

# ── GitHub Actions deploy role (OIDC) ─────────────────────────────────────────
# Allows GitHub Actions to push to ECR and update the ECS service without
# storing long-lived AWS credentials in GitHub Secrets.
#
# Set var.github_repo to "your-org/your-repo" to enable.
# Leave empty to skip (use static credentials instead).

variable "github_repo" {
  description = "GitHub repo allowed to assume the deploy role (e.g. acme/backend). Leave empty to skip OIDC setup."
  type        = string
  default     = ""
}

data "aws_caller_identity" "current" {}

resource "aws_iam_openid_connect_provider" "github" {
  count = var.github_repo != "" ? 1 : 0

  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "github_deploy" {
  count = var.github_repo != "" ? 1 : 0
  name  = "${var.project_name}-github-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github[0].arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_repo}:ref:refs/heads/main"
          }
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "github_deploy" {
  count = var.github_repo != "" ? 1 : 0
  name  = "ecr-ecs-deploy"
  role  = aws_iam_role.github_deploy[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ECRAuth"
        Effect = "Allow"
        Action = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "ECRPush"
        Effect = "Allow"
        Action = [
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
          "ecr:CompleteLayerUpload",
          "ecr:GetDownloadUrlForLayer",
          "ecr:InitiateLayerUpload",
          "ecr:PutImage",
          "ecr:UploadLayerPart",
        ]
        Resource = aws_ecr_repository.this.arn
      },
      {
        Sid    = "ECSDescribe"
        Effect = "Allow"
        Action = [
          "ecs:DescribeTaskDefinition",
          "ecs:DescribeServices",
        ]
        Resource = "*"
      },
      {
        Sid    = "ECSRegisterDeploy"
        Effect = "Allow"
        Action = [
          "ecs:RegisterTaskDefinition",
          "ecs:UpdateService",
        ]
        Resource = "*"
      },
      {
        Sid    = "PassExecutionRole"
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = [
          aws_iam_role.execution.arn,
          aws_iam_role.task.arn,
        ]
      }
    ]
  })
}

output "github_deploy_role_arn" {
  description = "Set this as AWS_DEPLOY_ROLE_ARN in GitHub repository secrets"
  value       = var.github_repo != "" ? aws_iam_role.github_deploy[0].arn : "OIDC not configured — set var.github_repo"
}
