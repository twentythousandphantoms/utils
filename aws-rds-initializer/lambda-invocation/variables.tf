
variable "function_name" {
  description = "Name of  lambda function"
  type        = string
  default     = ""
}

variable "user_env" {
  description = "Name of  the environment"
  type        = string
  default     = ""
}
variable "inputs_file" {
  description = "The file from which it picks variables"
  type        = string
  default     = ""
}


variable "realm" {
  description = "The realm which the account belongs to"
  type        = string
  default     = ""
}
variable "account-function" {
  description = "The account function"
  type        = string
  default     = "compute"
}

variable "account-name" {
  description = "The account name"
  type        = string
  default     = ""
}
