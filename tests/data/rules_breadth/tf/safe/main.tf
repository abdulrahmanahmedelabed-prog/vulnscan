provider "aws" {
  region     = "us-east-1"
  access_key = var.access_key
  secret_key = var.secret_key
}

resource "aws_s3_bucket_acl" "site" {
  bucket = aws_s3_bucket.site.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "site" {
  bucket                  = aws_s3_bucket.site.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:role/reader" }
      Action    = ["s3:GetObject"]
      Resource  = "arn:aws:s3:::site/*"
    }]
  })
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = true
}

resource "aws_ebs_volume" "restored" {
  availability_zone = "us-east-1a"
  snapshot_id       = "snap-0123456789abcdef0"
}

resource "aws_db_instance" "db" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  storage_encrypted   = true
  publicly_accessible = false
}

resource "aws_cloudtrail" "trail" {
  name                       = "main"
  enable_logging             = true
  enable_log_file_validation = true
}

resource "aws_kms_key" "app" {
  description         = "application data"
  enable_key_rotation = true
}

resource "aws_kms_key" "signing" {
  description              = "signing"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_2048"
}

resource "google_storage_bucket_iam_member" "reader" {
  bucket = google_storage_bucket.site.name
  role   = "roles/storage.objectViewer"
  member = "group:readers@corp.internal"
}

resource "azurerm_storage_account" "sa" {
  name                            = "appstorage"
  https_traffic_only_enabled      = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
}

resource "aws_eks_cluster" "eks" {
  name = "main"
  vpc_config {
    endpoint_public_access  = false
    endpoint_private_access = true
    public_access_cidrs     = ["203.0.113.0/24"]
  }
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "required"
  }
}

resource "azurerm_postgresql_server" "pg" {
  name                    = "pg"
  ssl_enforcement_enabled = true
}

resource "azurerm_mssql_firewall_rule" "office" {
  name             = "office"
  start_ip_address = "203.0.113.1"
  end_ip_address   = "203.0.113.254"
}

resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.web.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_security_group_rule" "egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.web.id
}

resource "azurerm_network_security_group" "nsg" {
  name = "nsg"
  security_rule {
    name                       = "ssh-internal"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "10.0.0.0/8"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "deny-rdp"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "https"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

resource "google_compute_firewall" "https" {
  name          = "https"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "iap_ssh" {
  name          = "iap-ssh"
  network       = "default"
  source_ranges = ["35.235.240.0/20"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_container_cluster" "gke" {
  name = "gke"
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block = "10.0.0.0/8"
    }
  }
}

# publicly_accessible = true
# storage_encrypted = false

# Deny-everything guard rails and conditioned principals are the safe idioms
data "aws_iam_policy_document" "tls_only" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

data "aws_iam_policy_document" "vpce" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceVpce"
      values   = ["vpce-1234"]
    }
  }
}
