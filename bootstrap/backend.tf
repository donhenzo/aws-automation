terraform {
  backend "s3" {
    key          = "henz-iga/bootstrap.tfstate"
    region       = "eu-north-1"
    use_lockfile = true
    # Pass the bucket at init time: terraform init -backend-config="bucket=<state bucket name>"
  }
}
