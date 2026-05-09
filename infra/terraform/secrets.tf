# Secrets Manager placeholders — Terraform creates the secret shells.
# Populate values after `terraform apply` before the first deployment:
#
#   aws secretsmanager put-secret-value \
#     --secret-id /perceptron/production/MONGODB_URI \
#     --secret-string 'mongodb+srv://...'
#
# Or use the AWS Console: Secrets Manager → select secret → "Retrieve secret value" → Edit.

resource "aws_secretsmanager_secret" "admin_secret_key" {
  name                    = "/${var.project_name}/${var.environment}/ADMIN_SECRET_KEY"
  description             = "Admin passphrase for /auth/login"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret" "auth_token_secret" {
  name                    = "/${var.project_name}/${var.environment}/AUTH_TOKEN_SECRET"
  description             = "JWT signing secret"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret" "mongodb_uri" {
  name                    = "/${var.project_name}/${var.environment}/MONGODB_URI"
  description             = "MongoDB Atlas connection string"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret" "resend_api_key" {
  name                    = "/${var.project_name}/${var.environment}/RESEND_API_KEY"
  description             = "Resend transactional email API key"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret" "cvat_internal_api_key" {
  name                    = "/${var.project_name}/${var.environment}/CVAT_INTERNAL_API_KEY"
  description             = "Internal API key for CVAT user provisioning"
  recovery_window_in_days = 7
}
