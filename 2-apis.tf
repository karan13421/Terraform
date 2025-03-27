
resource "google_project_service" "compute" {
  project = local.project_id
  service = "compute.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "iap" {
  project = local.project_id
  service = "iap.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "logging" {
  project = local.project_id
  service = "logging.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "storage" {
  project = local.project_id
  service = "storage.googleapis.com"
  disable_on_destroy = false
}

resource "google_compute_network" "custom_vpc" {
  name = "custom-vpc"
  depends_on = [google_project_service.compute]
}

resource "google_compute_subnetwork" "custom_subnet" {
  name          = "custom-subnet"
  network       = google_compute_network.custom_vpc.id
  ip_cidr_range = "10.0.0.0/24"
  region        = "us-central1"
}

resource "google_compute_firewall" "vpc_ssh_rule" {
  name    = "vpc-ssh-allow"
  network = google_compute_network.custom_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["allow-ssh"]
}

resource "google_storage_bucket" "audit_log_bucket" {
  name          = "your-audit-log-bucket"
  location      = "US"
  storage_class = "STANDARD"
  force_destroy = true
  depends_on = [google_project_service.storage]
}

resource "google_compute_instance" "vm_instance" {
  name         = "my-vm"
  machine_type = "e2-micro"  # Free tier eligible
  zone         = "us-central1-a"

  scheduling {
    preemptible       = true  # Spot instance to reduce costs
    provisioning_model = "SPOT"
    automatic_restart = false
  }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.custom_vpc.id
    subnetwork = google_compute_subnetwork.custom_subnet.id
  }

  metadata = {
    enable-oslogin = "TRUE"
  }
  tags = ["allow-ssh"]
  depends_on = [google_project_service.compute]
}

resource "google_project_iam_binding" "iap_ssh" {
  project = local.project_id
  role    = "roles/iap.tunnelResourceAccessor"
  members  = [for email in local.emails: "user:${email}"]
  depends_on = [google_project_service.iap]
}

resource "google_project_iam_binding" "os_login" {
  project = local.project_id
  role    = "roles/compute.osLogin"
  members = [for email in local.emails: "user:${email}"]
}


resource "google_logging_project_sink" "iap_audit_log" {
  name        = "iap-audit-logs"
  destination = "storage.googleapis.com/${google_storage_bucket.audit_log_bucket.name}"
  filter      = "protoPayload.methodName=\"google.cloud.iap.v1.GetTunnelDestGroup\""

  unique_writer_identity = true
  depends_on = [google_project_service.logging]
}

resource "google_storage_bucket_iam_binding" "audit_log_writer" {
  bucket = google_storage_bucket.audit_log_bucket.name
  role   = "roles/storage.objectCreator"

  members = [
    google_logging_project_sink.iap_audit_log.writer_identity
  ]
}
