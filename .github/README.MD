# Terraflops Terraform Module
 
### Application Load Balancer (For Blue/Green ECS Deployments)

This module is responsible for setting up an application load balancer to be used
with AWS CodeDeploy Blue/Green ECS deployments.

#### Example usage

```hcl-terraform
module "example_load_balancer" {
  source = "git::https://github.com/TerraFlops/aws-ecs-blue-green-load-balancer?ref=v1.0"
  name = 'example'

  # Setup log bucket
  log_bucket = 'example-log-bucket.example.com'
  log_bucket_create = true

  # Setup listener
  listener_port = 443
  listener_protocol = 'https'
  listener_certificate_arn = 'xxxxxxxxxxxxxxxxxxxxxxxxxx'

  # Setup target
  target_type = "ip"
  target_port = 8080
  target_protocol = "https"
  deregistration_delay = 60
  
  # Setup health check
  health_check_port = 8080
  health_check_url = "/health"
  health_check_protocol = "http"
  health_check_response_codes = ["200"]
  health_check_timeout = 5

  # Configure VPC settings
  vpc_id = 'vpc-xxxxxxxxxxxxxxxx'
  security_group_ids = [
    'sg-xxxxxxxxxxxxxxxx'
  ]
  subnet_ids = [
    'subnet-xxxxxxxxxxxxxxxx', 
    'subnet-yyyyyyyyyyyyyyyy' 
  ]
}
```
