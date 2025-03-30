output "file1_path" {
  description = "this the path of file m1"
  value = local_file.file1.filename
}   

output "file2_path" {
  description = "this the path of file 2 m1"
  value = local_file.file2.filename
}   


