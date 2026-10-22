terraform {
  backend "s3" {
    key          = "henz-iga/terraform.tfstate"
    region       = "eu-north-1"
    use_lockfile = true
    # The bucket name is not stored in the repo. Pass it when initialising:
    #   terraform init -backend-config="bucket=<state bucket name>"
  }
}
