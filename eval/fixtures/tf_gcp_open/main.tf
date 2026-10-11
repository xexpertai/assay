resource "google_compute_firewall" "allow_all" {
  name          = "allow-all"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22", "80"]
  }
}
resource "google_storage_bucket_iam_member" "public" {
  bucket = "acme-site"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
