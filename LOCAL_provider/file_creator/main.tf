resource "local_file" "file_name_m1" {
    count = 3
    filename = "${path.module}/example-${count.index}"
    content = "Hello"
}

resource "local_sensitive_file" "file_name_m2" {
  content  = "foo!"
  filename = "${path.module}/sensitive_example.txt"
}