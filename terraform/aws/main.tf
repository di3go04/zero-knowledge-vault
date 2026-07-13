terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

variable "region" { default = "us-east-1" }
variable "db_password" { type = string, sensitive = true }
variable "app_image" { default = "zk-vault:latest" }

provider "aws" { region = var.region }

# RDS PostgreSQL
resource "aws_db_instance" "vault_db" {
  identifier           = "zk-vault-db"
  engine               = "postgres"
  engine_version       = "16"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  db_name              = "zkvault"
  username             = "zkvault"
  password             = var.db_password
  skip_final_snapshot  = true
  publicly_accessible  = false
}

# ECS Cluster
resource "aws_ecs_cluster" "vault_cluster" {
  name = "zk-vault-cluster"
}

resource "aws_ecs_task_definition" "vault_task" {
  family                   = "zk-vault"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  container_definitions = jsonencode([{
    name  = "zk-vault"
    image = var.app_image
    portMappings = [{ containerPort = 3000 }]
    environment = [
      { name = "DATABASE_URL", value = "postgresql://zkvault:${var.db_password}@${aws_db_instance.vault_db.address}:5432/zkvault" }
      { name = "NODE_ENV", value = "production" }
    ]
  }])
}

resource "aws_ecs_service" "vault_service" {
  cluster         = aws_ecs_cluster.vault_cluster.id
  task_definition = aws_ecs_task_definition.vault_task.arn
  desired_count   = 2
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = ["subnet-xxx"]
    assign_public_ip = false
  }
}

output "db_endpoint" { value = aws_db_instance.vault_db.address }
output "ecs_cluster" { value = aws_ecs_cluster.vault_cluster.name }
