resource "local_file" "file_name" {
    count = 3
    filename = "${path.module}/example-${count.index}"
    content = "Hello"
}

resource "local_sensitive_file" "foo" {
  content  = "foo!"
  filename = "${path.module}/sensitive_example.txt"
}

resource "local_file" "new_file" {
  filename = "${var.filename_new}.txt"
  content = "NEW"
}


resource "local_file" "dynamic_file_creator" {
  count = "${var.count_num}"
  filename = "file-${count.index}.txt"
  content = "foo"
}


locals {
  environment = "dev"
  upper_case = upper(local.environment)
  base_path = "${path.module}/configs/${local.upper_case}"
}

resource "local_file" "service_configs" {
  filename = "${local.base_path}/server.sh"
  content = <<EOT
  environment = ${local.environment}
  port = 3000
  EOT
}

output "filename_1" {
  value = local_file.service_configs.filename
}