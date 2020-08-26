# Container name
output "container_name" {
  description = "The container name"
  value = aws_lb.application.name
}

# Application load balancer
output "alb_arn" {
  description = "The ARN of the application load balancer"
  value = aws_lb.application.arn
}

output "alb_dns_name" {
  description = "The DNS record for the application load balancer"
  value = aws_lb.application.dns_name
}

output "alb_listener_arn" {
  description = "The ARN of the application load balancer listener"
  value = aws_lb_listener.alb_listener.arn
}

# Blue target group
output "blue_target_group_arn" {
  description = "The ARN of the blue target group"
  value = aws_lb_target_group.blue.arn
}

output "blue_target_group_name" {
  description = "The name of the blue target group"
  value = aws_lb_target_group.blue.name
}

# Green target group
output "green_target_group_arn" {
  description = "The ARN of the green target group"
  value = aws_lb_target_group.green.arn
}

output "green_target_group_name" {
  description = "The name of the green target group"
  value = aws_lb_target_group.green.name
}
