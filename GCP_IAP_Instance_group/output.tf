output "https_load_balancer_ip" {
  description = "External IP assigned to the HTTPS forwarding rule"
  value       = google_compute_global_forwarding_rule.https_forwarding_rule.ip_address
}