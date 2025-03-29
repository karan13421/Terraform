

# Enable Required APIs
resource "google_project_service" "required_services" {
  for_each = toset([
    "compute.googleapis.com",
    "iap.googleapis.com",
    "logging.googleapis.com",
    "storage.googleapis.com"
  ])
  
  project            = local.project_id
  service            = each.key
  disable_on_destroy = false
}

# Create Custom VPC & Subnet
resource "google_compute_network" "custom_vpc" {
  name       = "custom-vpc"
  auto_create_subnetworks = false
  depends_on = [google_project_service.required_services]
}

resource "google_compute_subnetwork" "custom_subnet" {
  name          = "custom-subnet"
  network       = google_compute_network.custom_vpc.id
  ip_cidr_range = "10.0.0.0/24"
  region        = "us-central1"
}

# Create an Instance Template with FastAPI Startup Script
resource "google_compute_instance_template" "vm_template" {
  name         = "vm-template-${formatdate("YYYYMMDD-HHmmss", timestamp())}"
  machine_type = "e2-micro" # Free tier eligible
  
  disk {
    boot         = true
    auto_delete  = true
    source_image = "debian-cloud/debian-11"  # Correct way to define the image
  }

  network_interface {
    network    = google_compute_network.custom_vpc.id
    subnetwork = google_compute_subnetwork.custom_subnet.id
    access_config {} # Assigns an ephemeral external IP
  }

  scheduling {
    preemptible       = true # Spot instance to reduce costs
    provisioning_model = "SPOT"
    automatic_restart = false
  }

  metadata_startup_script = <<-EOT
#!/bin/bash
  nohup python3 -m http.server 3000
EOT

  metadata = {
    enable-oslogin = "TRUE"
  }

  tags = ["allow-fastapi", "allow-ssh"]

  lifecycle {
    create_before_destroy = true
  }
}

# Create a Managed Instance Group
resource "google_compute_instance_group_manager" "instance_group" {
  name               = "web-instance-group"
  base_instance_name = "web-instance"
  zone               = "us-central1-a"

  version {
    instance_template = google_compute_instance_template.vm_template.id
  }

  target_size = 1

    named_port {
    name = "http"
    port = 3000
  }

  update_policy {
    type                   = "PROACTIVE"   # Use "OPPORTUNISTIC" for cost-saving updates
    minimal_action         = "REPLACE"     # Or use "RESTART" if disk doesn't change
    max_surge_fixed        = 1             # Allows one extra instance during update
    max_unavailable_fixed  = 0             # Ensures no downtime
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.fastapi_health.id
    initial_delay_sec = 300
  }
  lifecycle {
    create_before_destroy = true
  }
}

# Health Check for FastAPI (Port 3000)
resource "google_compute_health_check" "fastapi_health" {
  name = "fastapi-health-check"

  http_health_check {
    port = 3000
    request_path = "/"
  }

  timeout_sec = 5
  check_interval_sec = 10
  healthy_threshold = 4
  unhealthy_threshold = 5
}

# Create a Backend Service (Port 3000)
resource "google_compute_backend_service" "backend_service" {
  name          = "fastapi-backend-service"
  protocol      = "HTTP"
  timeout_sec   = 30
  health_checks = [google_compute_health_check.fastapi_health.id]

  backend {
    group = google_compute_instance_group_manager.instance_group.instance_group
  }


  security_policy = google_compute_security_policy.iap_policy.id

  depends_on = [ 
    google_compute_health_check.fastapi_health,
    google_compute_security_policy.iap_policy]
}

# Create a URL Map
resource "google_compute_url_map" "url_map" {
  name            = "fastapi-url-map"
  default_service = google_compute_backend_service.backend_service.id
}

# Create an HTTP Target Proxy
resource "google_compute_target_http_proxy" "http_proxy" {
  name    = "fastapi-target-proxy"
  url_map = google_compute_url_map.url_map.id
}

# Create a Regional Forwarding Rule (Port 3000)
resource "google_compute_global_forwarding_rule" "http_forwarding_rule" {
  name       = "fastapi-forwarding-rule"
  target     = google_compute_target_http_proxy.http_proxy.id
  port_range = "80"
}

# Firewall Rule to Allow HTTP Traffic on Port 3000
resource "google_compute_firewall" "allow_fastapi" {
  name    = "allow-fastapi"
  network = google_compute_network.custom_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["3000"]
  }

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["allow-fastapi"]
}

# Firewall Rule to Allow SSH via IAP
resource "google_compute_firewall" "allow_ssh" {
  name    = "vpc-ssh-allow"
  network = google_compute_network.custom_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"] # IAP SSH range
  target_tags   = ["allow-ssh"]
}

# Firewall Rule to Allow Load Balancer Traffic to Backend Service
resource "google_compute_firewall" "allow_lb_to_backend" {
  name    = "allow-lb-to-backend"
  network = google_compute_network.custom_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["3000"]
  }

  direction     = "INGRESS"
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["allow-fastapi"]
}

# IAM Role to Allow IAP SSH
resource "google_project_iam_binding" "iap_ssh" {
  project = local.project_id
  role    = "roles/iap.tunnelResourceAccessor"
  members = [for email in local.emails: "user:${email}"]
  depends_on = [google_project_service.required_services]
}

# IAM Role for OS Login
resource "google_project_iam_binding" "os_login" {
  project = local.project_id
  role    = "roles/compute.osLogin"
  members = [for email in local.emails: "user:${email}"]
}

# Audit Logging for IAP
resource "google_project_iam_audit_config" "audit_config" {
  project = local.project_id
  service = "iap.googleapis.com"

  audit_log_config {
    log_type = "DATA_WRITE"
  }

  audit_log_config {
    log_type = "ADMIN_READ"
  }
}

resource "google_project_iam_binding" "iap_access" {
  project = local.project_id
  role    = "roles/iap.httpsResourceAccessor"

  members = [for email in local.emails : "user:${email}"]
}


resource "google_compute_security_policy" "iap_policy" {
  name = "iap-security-policy"

  rule {
    action   = "allow"
    priority = 1000

    match {
      expr {
        expression = "request.headers['x-goog-authenticated-user-email'] != ''"
      }
    }
  }

  # Add the required default rule
  rule {
    action   = "deny(403)"
    priority = 2147483647

    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}

# Logging Sink (Optional: Uncomment to save logs)
# resource "google_logging_project_sink" "iap_audit_logs" {
#   name        = "iap-audit-logs"
#   project     = local.project_id
#   destination = "logging.googleapis.com/projects/${local.project_id}/locations/global/buckets/_Default"
#   filter      = "logName:\"logs/cloudaudit.googleapis.com\" AND resource.type=\"iap_web\""
#   retention_days = 7
#   depends_on = [google_project_service.required_services]
# }


# Create a Self-Signed SSL Certificate
resource "google_compute_ssl_certificate" "self_signed_cert" {
  name        = "self-signed-cert"
  private_key = file("./private-key.pem") # Replace with the path to your private key
  certificate = file("./certificate.pem") # Replace with the path to your certificate
}

# Create an HTTPS Target Proxy
resource "google_compute_target_https_proxy" "https_proxy" {
  name             = "fastapi-https-proxy"
  url_map          = google_compute_url_map.url_map.id
  ssl_certificates = [google_compute_ssl_certificate.self_signed_cert.id]
}

# Create a Forwarding Rule for HTTPS (Port 443)
resource "google_compute_global_forwarding_rule" "https_forwarding_rule" {
  name       = "fastapi-https-forwarding-rule"
  target     = google_compute_target_https_proxy.https_proxy.id
  port_range = "443"
}


# Create a Logging Metric for IAP ADMIN_READ and DATA_WRITE
resource "google_logging_metric" "iap_admin_data_write" {
  name        = "iap_admin_data_write"
  description = "Metric for IAP ADMIN_READ and DATA_WRITE events"
  filter      = <<EOT
    (logName:"projects/${local.project_id}/logs/cloudaudit.googleapis.com%2Factivity" OR  logName:"projects/${local.project_id}/logs/cloudaudit.googleapis.com%2Fdata_access" ) AND 
    protoPayload.serviceName="iap.googleapis.com" AND severity>=NOTICE
  EOT
# (protoPayload.methodName:"google.cloud.iap.v1.IdentityAwareProxyAdminService" OR protoPayload.methodName:""  OR protoPayload.methodName:"google.cloud.audit.v1.DataWrite")
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Create an Alerting Policy
resource "google_monitoring_alert_policy" "iap_admin_alert" {
  display_name = "IAP ADMIN_READ & DATA_WRITE Alert"
  combiner     = "OR"
  conditions {
    display_name = "IAP Admin Read or Data Write Detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/iap_admin_data_write\" resource.type=\"gce_backend_service\""
      threshold_value = 1
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_MIN"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}

# Define a Notification Channel (Email)
resource "google_monitoring_notification_channel" "email" {
  display_name = "IAP Admin Alert Email"
  type         = "email"
  labels = {
    email_address = "karathore@deqode.com" # Replace with your email
  }
}