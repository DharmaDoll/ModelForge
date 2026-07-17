resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_db_instance" "payments" {
  identifier = "payments-db"
}

resource "aws_lambda_function" "api" {
  function_name = "payments-api"

  vpc_config {
    subnet_ids = [aws_subnet.private.id]
  }

  environment {
    variables = {
      DB_HOST = aws_db_instance.payments.address
    }
  }
}

resource "aws_lb" "public" {
  name     = "payments-public-lb"
  internal = false
}
