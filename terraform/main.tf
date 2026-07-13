# MEJORA 8/50: Terraform provider — IaC para provisioning.
# =====================================================================
# Provisiona una instancia del Zero-Knowledge Vault en cualquier cloud.
# Uso: terraform init && terraform apply

terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

variable "session_secret" {
  description = "Secreto para firmar tokens HS256 (mín 32 chars)"
  type        = string
  sensitive   = true
}

variable "redis_url" {
  description = "URL de Redis (opcional, sin esto usa Map in-memory)"
  type        = string
  default     = ""
}

resource "docker_network" "zk_network" {
  name = "zk-vault-network"
}

resource "docker_image" "zk_vault" {
  name = "zk-vault:latest"
  build {
    context = "."
    dockerfile = "Dockerfile"
  }
}

resource "docker_container" "zk_vault_app" {
  name     = "zk-vault-app"
  image    = docker_image.zk_vault.image_id
  networks = [docker_network.zk_network.name]

  ports {
    internal = 3000
    external = 3000
  }

  env = [
    "NODE_ENV=production",
    "DATABASE_URL=file:/app/data/vault.db",
    "SESSION_SECRET=${var.session_secret}",
    var.redis_url != "" ? "REDIS_URL=${var.redis_url}" : "REDIS_URL="
  ]

  volumes {
    host_path = "${abspath(path.module)}/data"
    container_path = "/app/data"
  }

  healthcheck {
    test     = ["CMD", "wget", "-qO-", "http://localhost:3000/api/health"]
    interval = "30s"
    timeout  = "5s"
    retries  = 3
  }

  restart = "unless-stopped"
}

resource "docker_container" "zk_redis" {
  count    = var.redis_url == "" ? 1 : 0
  name     = "zk-redis"
  image    = "redis:7-alpine"
  networks = [docker_network.zk_network.name]

  ports {
    internal = 6379
    external = 6379
  }

  volumes {
    host_path = "${abspath(path.module)}/redis-data"
    container_path = "/data"
  }

  restart = "unless-stopped"
}

output "app_url" {
  value = "http://localhost:3000"
}

output "health_endpoint" {
  value = "http://localhost:3000/api/health"
}
