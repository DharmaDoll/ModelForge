resource "aws_db_instance" "db" {
  identifier = "orders-db"
}

resource "aws_lb" "private" {
  name       = "private-lb"
  internal   = true
  depends_on = [aws_db_instance.db]
}
