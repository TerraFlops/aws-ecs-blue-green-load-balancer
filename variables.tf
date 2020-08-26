variable "name" {
  description = "Name to assign to the ALB"
  type = string
}

variable "tags" {
  description = "Optional tags to associate with ALB resources"
  type = map(string)
  default = {}
}

variable "vpc_id" {
  description = "The AWS resource ID of the VPC where this should be provisioned"
  type = string
}

variable "enable_deletion_protection" {
  description = "Boolean flag, if true deletion protection will be enabled. Defaults to false"
  type = bool
  default = false
}

variable "log_bucket" {
  description = "The name of the log bucket to which ALB logs will be written"
  type = string
}

variable "log_bucket_create" {
  description = "Boolean flag, if true the S3 log bucket will be created"
  type = bool
  default = false
}

variable "internal" {
  description = "Boolean flag indicating whether the load balancer is public facing or internal. If not specified default to public"
  type = bool
  default = false
}

# Listener settings

variable "listener_port" {
  description = "The port number on which the ALB will listen for traffic. Defaults to 443"
  type = number
  default = 443
}

variable "listener_protocol" {
  description = "The protocol it will use when listening for traffic. Defaults to HTTPS"
  type = string
  default = "HTTPS"
}

variable "listener_ssl_policy" {
  description = "The SSL neogitation policy that will be used. Defaults to ELBSecurityPolicy-2016-08"
  type = string
  default = "ELBSecurityPolicy-2016-08"
}

variable "listener_certificate_arn" {
  description = "The ARN of the ACM certificate that will be presented to incoming traffic"
  type = string
  default = null
}

# Target container settings

variable "target_port" {
  description = "The internal port number that is exposed on the ECS container to which traffic will be directed. Defaults to 443"
  type = number
  default = 443
}

variable "target_type" {
  description = "The target type for the ALB. Defaults to 'ip'"
  type = string
  default = "ip"
}

variable "deregistration_delay" {
  description = "The deregistration delay prior to deregistering servers. Defaults to 60 seconds"
  type = number
  default = 60
}

variable "target_protocol" {
  description = "The protocol it will use when communicating with the ECS container. Defaults to HTTPS"
  type = string
  default = "HTTPS"
}

# Health check settings

variable "health_check_url" {
  description = "The URL that will be used when performing health checks. Defaults to '/health'"
  type = string
  default = "/health"
}

variable "health_check_port" {
  description = "The port that will be used when performing health checks"
  type = number
}

variable "health_check_protocol" {
  description = "The protocol that will be used when performing health checks. Defaults to HTTPS"
  type = string
  default = "HTTPS"
}

variable "health_check_response_codes" {
  description = "Comma-separated list of HTTP status codes which will be treated as a successful health check. Defaults to 200"
  type = string
  default = "200"
}

variable "health_check_timeout" {
  description = "The number of seconds the health check will wait for a response. Defaults to 5"
  type = number
  default = 5
}

# VPC settings

variable "security_group_ids" {
  description = "Optional set of security group IPs to be applied to the ALB"
  type = set(string)
  default = []
}

variable "subnet_ids" {
  description = "Set of subnet IDs in which the ALB will be provisioned"
  type = set(string)
}
