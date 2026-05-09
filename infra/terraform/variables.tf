variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Short identifier used in every resource name"
  type        = string
  default     = "perceptron"
}

variable "environment" {
  description = "Deployment environment (production, staging)"
  type        = string
  default     = "production"
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "container_port" {
  description = "Port the Node.js server listens on"
  type        = number
  default     = 4000
}

variable "task_cpu" {
  description = "Fargate task vCPU units (256 = 0.25 vCPU)"
  type        = string
  default     = "256"
}

variable "task_memory" {
  description = "Fargate task memory in MiB"
  type        = string
  default     = "512"
}

variable "desired_count" {
  description = "Initial number of running tasks"
  type        = number
  default     = 1
}

variable "min_capacity" {
  description = "Auto-scaling minimum task count"
  type        = number
  default     = 1
}

variable "max_capacity" {
  description = "Auto-scaling maximum task count"
  type        = number
  default     = 4
}

# ── Non-sensitive application config ──────────────────────────────────────────

variable "token_expiry" {
  type    = string
  default = "30m"
}

variable "allowed_origins" {
  description = "Comma-separated CORS allowed origins"
  type        = string
  default     = ""
}

variable "from_email" {
  type    = string
  default = "Perceptron <noreply@perceptronai.org>"
}

variable "cvat_api_url" {
  description = "Internal CVAT API base URL reachable by the backend"
  type        = string
  default     = ""
}

variable "cvat_public_url" {
  description = "Public-facing CVAT URL shown in welcome emails"
  type        = string
  default     = ""
}

variable "contact_notify_email" {
  type    = string
  default = "support@perceptronai.org"
}

# ── TLS ───────────────────────────────────────────────────────────────────────

variable "certificate_arn" {
  description = "ACM certificate ARN for HTTPS. Leave empty to use HTTP only (fine for dev)."
  type        = string
  default     = ""
}
