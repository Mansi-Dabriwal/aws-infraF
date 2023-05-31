variable "region" {
  default = "us-east-1"
}


variable "cidr_block_vpc" {
  default = "10.0.0.0/16"
}

variable "env" {
  default = "dev"
}

variable "subnet_public_name_1" {
  default = "dev-public-1"
}

variable "subnet_public_name_2" {
  default = "dev-public-2"
}

variable "subnet_public_name_3" {
  default = "dev-public-3"
}

variable "cidr_subnet_1" {
  default = "10.0.1.0/24"
}

variable "cidr_subnet_2" {
  default = "10.0.2.0/24"
}

variable "cidr_subnet_3" {
  default = "10.0.3.0/24"
}


variable "subnet_private_name_1" {
  default = "dev-private-1"
}

variable "subnet_private_name_2" {
  default = "dev-private-2"
}

variable "subnet_private_name_3" {
  default = "dev-private-3"
}

variable "cidr_subnet_4" {
  default = "10.0.4.0/24"
}

variable "cidr_subnet_5" {
  default = "10.0.5.0/24"
}

variable "cidr_subnet_6" {
  default = "10.0.6.0/24"
}

variable "cidr_ig" {
  default = "0.0.0.0/0"
}

variable "public_launch" {
  default = "true"
}

variable "private_launch" {
  default = "false"
}

variable "database_username" {
  default = "csye6225"
}
variable "database_password" {
  default = "Mansi2875"
}

variable "database_hostname" {
  default = "Mansi2875"
}

variable "ami_id" {
  default = "ami-0bcf79671ff2ee201"
}

variable "sse_algorithm" {
  default = "AES256"
}

variable "instance_profile" {
  default = "instance_profile"
}

variable "S3-policy-attach" {
  default = "S3-policy-attach"
}

variable "instance_type" {
  default = "t2.micro"
}

variable "volume_size" {
  default = 50
}

variable "volume_type" {
  default = "gp2"
}

variable "device_name" {
  default = "/dev/xvda"
}

variable "engine" {
  default = "postgres"
}

variable "engine_version" {
  default = 13.7
}

variable "instance_class" {
  default = "db.t3.micro"
}

variable "db_name" {
  default = "csye6225"
}

variable "username" {
  default = "csye6225"
}

variable "password" {
  default = "Mansi2875"
}

variable "storage_class" {
  default = "STANDARD_IA"
}

variable "allocated_storage" {
  default = 10
}

variable "identifier" {
  default = "app-rds-db"
}
variable "zone_id" {
  default = "Z02421351EUG04XTR9K1K"
}
variable "route_53_name" {
  default = "dev4.dabriwalm.me"
}
variable "aws_launch_template_name" {
  default = "asg_launch_config"
}
variable "key_name" {
  default = "packer_63f648b7-978e-d647-07b3-0816800e268c"
}

variable "asg_name" {
  default = "csye6225-asg-spring2023"
}

variable "policy_type" {
  default = "SimpleScaling"
}

variable "adjustment_type" {
  default = "ChangeInCapacity"
}

variable "aws_lb_target_group_name" {
  default = "csye6225-lb-alb-tg"
}
variable "aws_lb_name" {
  default = "csye6225-lb"
}
variable "metric_name" {
  default = "CPUUtilization"
}

variable "alarm_name_up" {
  default = "alarm_scale_up"
}

variable "alarm_name_down" {
  default = "alarm_scale_down"
}

variable "comparison_operator_down" {
  default = "LessThanOrEqualToThreshold"
}

variable "comparison_operator_up" {
  default = "GreaterThanOrEqualToThreshold"
}

variable "statistic" {
  default = "Average"
}
variable "namespace" {
  default = "AWS/EC2"
}
variable "aws_autoscaling_policy_up_name" {
  default = "autoscaling_up_policy"
}

variable "aws_autoscaling_policy_down_name" {
  default = "autoscaling_down_policy"
}

variable "scaling_adjustment_up" {
  default = "1"
}

variable "scaling_adjustment_down" {
  default = "-1"
}
variable "alarm_description" {
  default = "This metric monitors ec2 cpu utilization"
}
variable "target_type" {
  default = "instance"
}
variable "load_balancer_type" {
  default = "application"
}

variable "certificate_arn" {
  default = "arn:aws:acm:us-east-1:083968887191:certificate/4f85005c-c20b-47b3-b732-c68176cf4eac"
}
variable "customer_master_key_spec" {
  default = "SYMMETRIC_DEFAULT"
}
variable "key_usage" {
  default = "ENCRYPT_DECRYPT"
}