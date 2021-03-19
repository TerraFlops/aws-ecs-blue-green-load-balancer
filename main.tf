locals {
  container_name = join("", [ for element in split("_", var.name): title(lower(element)) ])

  blue_target_group_name = "${local.container_name}TargetGroupBlue"
  green_target_group_name = "${local.container_name}TargetGroupGreen"
}

resource "aws_s3_bucket" "log_bucket" {
  count = var.log_bucket_create == true ? 1 : 0
  bucket = var.log_bucket
  versioning {
    enabled = true
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  policy = data.aws_iam_policy_document.log_bucket.json
}

resource "aws_s3_bucket_public_access_block" "log_bucket" {
  count = var.log_bucket_create == true ? 1 : 0
  bucket = aws_s3_bucket.log_bucket[count.index].bucket
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

data "aws_caller_identity" "default" {}

# Setup bucket policy allowing ALB to write logs (https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html)
data "aws_iam_policy_document" "log_bucket" {
  version = "2012-10-17"
  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject"
    ]
    resources = [
      "arn:aws:s3:::${var.log_bucket}/${var.name}/AWSLogs/${data.aws_caller_identity.default.account_id}/*"
    ]
    principals {
      identifiers = ["arn:aws:iam::783225319266:root"]
      type = "AWS"
    }
  }
  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject"
    ]
    resources = [
      "arn:aws:s3:::${var.log_bucket}/${var.name}/AWSLogs/${data.aws_caller_identity.default.account_id}/*"
    ]
    principals {
      identifiers = ["delivery.logs.amazonaws.com"]
      type = "Service"
    }
    condition {
      test = "StringEquals"
      values = [
        "bucket-owner-full-control"
      ]
      variable = "s3:x-amz-acl"
    }
  }
  statement {
    effect = "Allow"
    actions = [
      "s3:GetBucketAcl"
    ]
    resources = [
      "arn:aws:s3:::${var.log_bucket}"
    ]
    principals {
      identifiers = ["delivery.logs.amazonaws.com"]
      type = "Service"
    }
  }
  statement {
    sid = "DenyInsecureCommunications"
    effect = "Deny"
    principals {
      identifiers = ["*"]
      type = "AWS"
    }
    actions = ["s3:*"]
    resources = [
      "arn:aws:s3:::${var.log_bucket}",
      "arn:aws:s3:::${var.log_bucket}/*"
    ]
    condition {
      test = "Bool"
      values = ["false"]
      variable = "aws:SecureTransport"
    }
  }
}

# Create application load balancer
resource "aws_lb" "application" {
  name = var.name
  internal = var.internal
  load_balancer_type = "application"
  enable_deletion_protection = var.enable_deletion_protection
  drop_invalid_header_fields = true
  security_groups = var.security_group_ids
  subnets = var.subnet_ids

  access_logs {
    bucket = var.log_bucket_create == true ? aws_s3_bucket.log_bucket[0].bucket : var.log_bucket
    prefix = var.name
    enabled = true
  }

  tags = merge(var.tags, {
    Name = var.name
    LogBucketName = var.log_bucket
    GreenTargetGroupName = local.green_target_group_name
    BlueTargetGroupName = local.blue_target_group_name
  })
}

# Create blue target group
resource "aws_lb_target_group" "blue" {
  name = local.blue_target_group_name
  port = var.target_port
  protocol = upper(var.target_protocol)
  target_type = "ip"
  vpc_id = var.vpc_id
  deregistration_delay = var.deregistration_delay

  health_check {
    path = var.health_check_url
    port = var.health_check_port
    matcher = var.health_check_response_codes
    timeout = var.health_check_timeout
    protocol = upper(var.health_check_protocol)
  }

  tags = merge(var.tags, {
    Name = local.blue_target_group_name
    ApplicationLoadBalancerName = var.name
  })
}

# Create green target group
resource "aws_lb_target_group" "green" {
  name = local.green_target_group_name
  port = var.target_port
  protocol = upper(var.target_protocol)
  target_type = var.target_type
  vpc_id = var.vpc_id
  deregistration_delay = var.deregistration_delay

  health_check {
    path = var.health_check_url
    port = var.health_check_port
    matcher = var.health_check_response_codes
    timeout = var.health_check_timeout
    protocol = upper(var.health_check_protocol)
  }

  tags = merge(var.tags, {
    Name = local.green_target_group_name
    ApplicationLoadBalancerName = var.name
  })
}

# Create listener
resource "aws_lb_listener" "alb_listener" {
  load_balancer_arn = aws_lb.application.arn
  port = var.listener_port
  protocol = upper(var.listener_protocol)
  certificate_arn = upper(var.listener_protocol) == "HTTPS" ? var.listener_certificate_arn : null
  ssl_policy = upper(var.listener_protocol) == "HTTPS" ? var.listener_ssl_policy : null

  # Default action will forward to the green target group
  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.green.arn
  }
}
