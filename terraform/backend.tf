terraform {
  # The lifecycle supplies an absolute path outside the checkout.
  # Manual initialization uses backend.hcl.example with an absolute local path.
  backend "local" {}
}
