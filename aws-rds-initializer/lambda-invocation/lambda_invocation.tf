resource "random_pet" "rebuild_again_please" {}


data "aws_lambda_invocation" "lambda_invoke" {

  function_name = var.function_name

  input = file("accounts/${var.realm}/${var.account-function}/${var.account-name}/${var.user_env}/inputs/${var.inputs_file}.json")
}

