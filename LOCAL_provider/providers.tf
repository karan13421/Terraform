terraform {
    backend "local" {
      path = "../state-file/terraform.tfstate"
    }
  required_providers {
    local = {
      source = "hashicorp/local"
      version = "2.5.2"
    }
  }
}