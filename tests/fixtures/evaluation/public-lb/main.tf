resource "aws_lb" "public" {
  name     = "public-lb"
  internal = false
}
