aws_region   = "us-east-1"
project_name = "perceptron"
environment  = "production"

container_port = 4000
task_cpu       = "256"
task_memory    = "512"
desired_count  = 1
min_capacity   = 1
max_capacity   = 4

allowed_origins      = "https://perceptron-8priuevfx-rohanmainalis-projects.vercel.app,https://www.perceptronai.org,https://perceptronteam.vercel.app"
from_email           = "Auta <noreply@perceptronai.org>"
cvat_api_url         = "https://auta.perceptronai.org"
cvat_public_url      = "https://auta.perceptronai.org"
contact_notify_email = "support@perceptronai.org"
token_expiry         = "30m"

# Set to your GitHub repo to enable keyless OIDC CI/CD
github_repo = "RohanMainali/perceptron-backend"

# Uncomment once you have an ACM certificate for your domain
# certificate_arn = ""
