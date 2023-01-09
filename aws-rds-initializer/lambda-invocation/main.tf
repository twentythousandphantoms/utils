terraform {
  required_version = ">= 0.12"
  backend "s3" {
    bucket = {}
    key    = {}

    # NOTE: This is the region the state s3 bucket is in, not the region the aws provider will deploy into
    region         = "us-east-1"
    dynamodb_table = {}
    encrypt        = true
    role_arn = {}
    # profile        = "sandbox"
  }
}

provider "aws" {
  region = "us-east-1"
  # profile             = "sandbox"
  # allowed_account_ids = ["", ""]
}


provider "aws" {
  alias  = "secondary"
  region = "us-west-2"
  # profile             = "sandbox"
  # allowed_account_ids = ["", ""]
}


provider "aws" {
  alias = "primary"
  #version = "~> 2.23.0"
  region = "us-east-1"
  //profile             = "sandbox"
  # allowed_account_ids = ["", ""]
}
