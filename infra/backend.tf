terraform {
  backend "s3" {
    bucket       = "henz-iga-tfstate-416338380915-eu-north-1"
    key          = "henz-iga/terraform.tfstate"
    region       = "eu-north-1"
    use_lockfile = true
  }
}