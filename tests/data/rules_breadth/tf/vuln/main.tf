provider "aws" {
  region     = "us-east-1"
  # expect-next: TF015
  secret_key = "q1w2e3r4t5y6u7i8o9p0"
}

resource "aws_s3_bucket_acl" "site" {
  bucket = aws_s3_bucket.site.id
  # expect-next: TF001
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "site" {
  bucket = aws_s3_bucket.site.id
  # expect-next: TF002
  block_public_acls = false
}

resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      # expect-next: TF003
      Principal = "*"
      # expect-next: TF004
      Action    = "*"
      Resource  = "*"
    }]
  })
}

# expect-next: TF020
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 10
}

resource "aws_ebs_volume" "logs" {
  availability_zone = "us-east-1a"
  size              = 10
  # expect-next: TF005
  encrypted         = false
}

# expect-next: TF020
resource "aws_db_instance" "db" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  # expect-next: TF006
  publicly_accessible = true
}

resource "aws_cloudtrail" "trail" {
  name           = "main"
  # expect-next: TF007
  enable_logging = false
}

# expect-next: TF021
resource "aws_kms_key" "app" {
  description = "application data"
}

resource "aws_kms_key" "logs" {
  description         = "logs"
  # expect-next: TF008
  enable_key_rotation = false
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.site.name
  role   = "roles/storage.objectViewer"
  # expect-next: TF009
  member = "allUsers"
}

resource "google_storage_bucket_iam_binding" "public" {
  bucket = google_storage_bucket.site.name
  role   = "roles/storage.objectViewer"
  members = [
    # expect-next: TF009
    "allAuthenticatedUsers",
  ]
}

resource "azurerm_storage_account" "sa" {
  name                            = "appstorage"
  # expect-next: TF010
  https_traffic_only_enabled      = false
  # expect-next: TF011
  min_tls_version                 = "TLS1_0"
  # expect-next: TF016
  allow_nested_items_to_be_public = true
}

resource "aws_eks_cluster" "eks" {
  name = "main"
  vpc_config {
    # expect-next: TF012
    endpoint_public_access = true
    # expect-next: TF013
    public_access_cidrs    = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  metadata_options {
    # expect-next: TF014
    http_tokens = "optional"
  }
}

resource "azurerm_postgresql_server" "pg" {
  name                    = "pg"
  # expect-next: TF017
  ssl_enforcement_enabled = false
}

resource "azurerm_mssql_firewall_rule" "all" {
  name             = "all"
  start_ip_address = "0.0.0.0"
  # expect-next: TF018
  end_ip_address   = "255.255.255.255"
}

resource "aws_security_group" "ssh" {
  name = "ssh"
  # expect-next: TF019
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# expect-next: TF019
resource "aws_vpc_security_group_ingress_rule" "everything" {
  security_group_id = aws_security_group.ssh.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# expect-next: TF019
resource "aws_security_group_rule" "rdp" {
  type              = "ingress"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  ipv6_cidr_blocks  = ["::/0"]
  security_group_id = aws_security_group.ssh.id
}

resource "azurerm_network_security_group" "nsg" {
  name = "nsg"
  # expect-next: TF019
  security_rule {
    name                       = "rdp"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "google_compute_firewall" "ssh" {
  name          = "ssh"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  # expect-next: TF019
  allow {
    protocol = "tcp"
    ports    = ["20-30"]
  }
}

resource "google_container_cluster" "gke" {
  name = "gke"
  master_authorized_networks_config {
    cidr_blocks {
      # expect-next: TF022
      cidr_block = "0.0.0.0/0"
    }
  }
}

resource "google_sql_database_instance" "sql" {
  name = "sql"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      authorized_networks {
        name  = "anyone"
        # expect-next: TF022
        value = "0.0.0.0/0"
      }
    }
  }
}

# commented-out settings are not configuration
# publicly_accessible = true

data aws_iam_policy_document "open" {
  statement {
    effect = "Allow"
    # expect-next: TF004
    actions   = ["*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      # expect-next: TF003
      identifiers = ["*"]
    }
  }
}

resource "azurerm_role_definition" "god" {
  name  = "god"
  scope = "/subscriptions/x"
  permissions {
    # expect-next: TF004
    actions = [
      "*",
    ]
  }
}
