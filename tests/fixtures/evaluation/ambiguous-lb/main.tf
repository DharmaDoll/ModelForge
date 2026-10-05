variable "is_internal" {
  type = bool
}

resource "aws_lb" "public_named" {
  name     = "public-facing-name-only"
  internal = var.is_internal
}
