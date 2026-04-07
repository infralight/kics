resource "aws_s3_bucket" "example" {
  bucket = "example-insecure-bucket"
  acl    = "public-read" # KICS Violation: S3 bucket should not have public read access

  versioning {
    enabled = false # KICS Violation: S3 bucket versioning is disabled
  }
}

resource "aws_security_group" "insecure_sg" {
  name        = "example-insecure-sg"
  description = "Allow all traffic"
  vpc_id      = "vpc-123456"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # KICS Violation: Open to the world
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "example" {
  name        = "example-insecure-policy"
  description = "Example IAM policy with wildcard actions"

  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "*", # KICS Violation: IAM policies should not allow all actions
        "Effect": "Allow",
        "Resource": "*"
      }
    ]
  })
}

terraform {
  backend "s3" {
    bucket  = "xvoucher-terraform-cit"
    key     = "cit/common/terraform.tfstate"
    region  = "us-east-1"
    profile = "aws-cit"
  }
}

provider "aws" {
  region  = local.config.region
  profile = local.config.profile
  default_tags {
    tags = {
      CreatedBy     = local.created_by
      Environment   = local.xvoucher_environment_name
      iac-provider  = local.iac_provider
      iac-base-path = replace(path.cwd, "/.*(${local.terraform_git_repo}/.*)/", "$1")
    }
  }
}
