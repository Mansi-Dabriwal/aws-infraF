# Creating VPC,name, CIDR and Tags
resource "aws_vpc" "myvpc" {
  cidr_block       = var.cidr_block_vpc
  instance_tenancy = "default"
  tags = {
    Name = var.env
  }
}

# Creating Public Subnets in VPC
resource "aws_subnet" "subnet-public-1" {
  vpc_id                  = aws_vpc.myvpc.id
  cidr_block              = var.cidr_subnet_1
  map_public_ip_on_launch = var.public_launch
  availability_zone       = "${var.region}a"

  tags = {
    Name = var.subnet_public_name_1
  }
}

resource "aws_subnet" "subnet-public-2" {
  vpc_id                  = aws_vpc.myvpc.id
  cidr_block              = var.cidr_subnet_2
  map_public_ip_on_launch = var.public_launch
  availability_zone       = "${var.region}b"

  tags = {
    Name = var.subnet_public_name_2
  }
}

resource "aws_subnet" "subnet-public-3" {
  vpc_id                  = aws_vpc.myvpc.id
  cidr_block              = var.cidr_subnet_3
  map_public_ip_on_launch = var.public_launch
  availability_zone       = "${var.region}c"

  tags = {
    Name = var.subnet_public_name_3
  }
}

# Creating Private Subnets in VPC
resource "aws_subnet" "subnet-private-1" {
  vpc_id                  = aws_vpc.myvpc.id
  cidr_block              = var.cidr_subnet_4
  map_public_ip_on_launch = var.private_launch
  availability_zone       = "${var.region}a"

  tags = {
    Name = var.subnet_private_name_1
  }
}

resource "aws_subnet" "subnet-private-2" {
  vpc_id                  = aws_vpc.myvpc.id
  cidr_block              = var.cidr_subnet_5
  map_public_ip_on_launch = var.private_launch
  availability_zone       = "${var.region}b"

  tags = {
    Name = var.subnet_private_name_2
  }
}

resource "aws_subnet" "subnet-private-3" {
  vpc_id                  = aws_vpc.myvpc.id
  cidr_block              = var.cidr_subnet_6
  map_public_ip_on_launch = var.private_launch
  availability_zone       = "${var.region}c"

  tags = {
    Name = var.subnet_private_name_3
  }
}

# Creating Internet Gateway in AWS VPC
resource "aws_internet_gateway" "myGateway" {
  vpc_id = aws_vpc.myvpc.id

  tags = {
    Name = var.env
  }
}

# Creating Route Tables for Internet gateway
resource "aws_route_table" "myroute" {
  vpc_id = aws_vpc.myvpc.id
  route {
    cidr_block = var.cidr_ig
    gateway_id = aws_internet_gateway.myGateway.id
  }

  tags = {
    Name = var.env
  }
}

# Creating Route Tables for Private Subnet
resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.myvpc.id
  tags = {
    Name = "private_route"
  }
}

# Creating Route Associations public subnets
resource "aws_route_table_association" "route-public-1" {
  subnet_id      = aws_subnet.subnet-public-1.id
  route_table_id = aws_route_table.myroute.id
}

resource "aws_route_table_association" "route-public-2" {
  subnet_id      = aws_subnet.subnet-public-2.id
  route_table_id = aws_route_table.myroute.id
}

resource "aws_route_table_association" "route-public-3" {
  subnet_id      = aws_subnet.subnet-public-3.id
  route_table_id = aws_route_table.myroute.id
}

# Creating Route Associations private subnets
resource "aws_route_table_association" "route-private-1" {
  subnet_id      = aws_subnet.subnet-private-1.id
  route_table_id = aws_route_table.private_route_table.id
}

resource "aws_route_table_association" "route-private-2" {
  subnet_id      = aws_subnet.subnet-private-2.id
  route_table_id = aws_route_table.private_route_table.id
}

resource "aws_route_table_association" "route-private-3" {
  subnet_id      = aws_subnet.subnet-private-3.id
  route_table_id = aws_route_table.private_route_table.id
}


# Create a security group for the EC2 instance:
resource "aws_security_group" "application" {
  name_prefix = "application"
  description = "Security group for web application"

  vpc_id = aws_vpc.myvpc.id


  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port = 8080
    to_port   = 8080
    protocol  = "tcp"

    security_groups = [aws_security_group.load_balancer.id]
    # cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    # description = "Allow Postgres traffic fromy the application security group"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    # description = "Allow Postgres traffic fromy the application security group"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Create a security group for the RDS instance:
resource "aws_security_group" "database" {
  name        = "database"
  description = "Security group for RDS"
  vpc_id      = aws_vpc.myvpc.id

  ingress {
    description     = "Allow Postgres traffic fromy the application security group"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id]
  }

  tags = {
    Name = "database"
  }

}

#Security group for Load Balancer
resource "aws_security_group" "load_balancer" {
  name        = "load_balancer"
  description = "Security group for load balancer"
  vpc_id      = aws_vpc.myvpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }


  tags = {
    Name = "load_balancer"
  }

}

#Create a db subnet group
resource "aws_db_subnet_group" "private_subnet_group" {
  description = "Subnet group for RDS instance"

  subnet_ids = [
    aws_subnet.subnet-private-1.id,
    aws_subnet.subnet-private-2.id,
    aws_subnet.subnet-private-3.id
  ]
  tags = {
    "Name" = "db-subnet-group"
  }
}

#Parameter group
resource "aws_db_parameter_group" "rds_parameter_group" {
  name_prefix = "rds-parameter-group"
  family      = "postgres13"
  description = "RDS DB parameter group for postgres 13"
}

#AWS-kms key for RDS
resource "aws_kms_key" "kms-rds" {
  description              = "KMS key for RDS"
  key_usage                = var.key_usage
  customer_master_key_spec = var.customer_master_key_spec
  deletion_window_in_days  = 7
  policy = jsonencode({
    "Id" : "key-consolepolicy-3",
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "Enable IAM User Permissions",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::083968887191:root"
        },
        "Action" : "kms:*",
        "Resource" : "*"
      },
      {
        "Sid" : "Allow use of the key",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::083968887191:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS"
        },
        "Action" : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "Allow attachment of persistent resources",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::083968887191:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS"
        },
        "Action" : [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant"
        ],
        "Resource" : "*",
        "Condition" : {
          "Bool" : {
            "kms:GrantIsForAWSResource" : "true"
          }
        }
      }
    ]
  })
}

#RDS key alias
resource "aws_kms_alias" "rds_key_alias" {
  name          = "alias/rds_key"
  target_key_id = aws_kms_key.kms-rds.key_id
}

#AWS-kms key for EC2
resource "aws_kms_key" "kms-ec2" {
  description              = "KMS key for EC2"
  key_usage                = var.key_usage
  customer_master_key_spec = var.customer_master_key_spec
  deletion_window_in_days  = 7
  policy = jsonencode({
    "Id" : "key-consolepolicy-3",
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "Enable IAM User Permissions",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::083968887191:root"
        },
        "Action" : "kms:*",
        "Resource" : "*"
      },
      {
        "Sid" : "Allow access for Key Administrators",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::083968887191:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        },
        "Action" : [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "Allow use of the key",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::083968887191:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        },
        "Action" : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "Allow attachment of persistent resources",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::083968887191:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        },
        "Action" : [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant"
        ],
        "Resource" : "*",
        "Condition" : {
          "Bool" : {
            "kms:GrantIsForAWSResource" : "true"
          }
        }
      }
    ]
  })

}

#EC2 key alias
resource "aws_kms_alias" "ec2_key_alias" {
  name          = "alias/ec2_key"
  target_key_id = aws_kms_key.kms-ec2.key_id
}

#Create a DB instance 
resource "aws_db_instance" "rds_instance" {
  allocated_storage      = var.allocated_storage
  identifier             = var.identifier
  engine                 = var.engine //Database Engine
  engine_version         = var.engine_version
  instance_class         = var.instance_class               //DB instance class
  db_name                = var.db_name                      //Database name
  multi_az               = false                            //multi az deployment - NO
  username               = var.username                     //username for the master DB user
  password               = var.password                     //master password
  publicly_accessible    = false                            // public accessiblity - NO
  vpc_security_group_ids = [aws_security_group.database.id] //db security group
  #   db_subnet_group_name = [aws_subnet.subnet-private-1.id] //Subnet Group
  db_subnet_group_name = aws_db_subnet_group.private_subnet_group.name //Subnet Group
  skip_final_snapshot  = true
  # final_snapshot_identifier = "backup"
  parameter_group_name = aws_db_parameter_group.rds_parameter_group.name
  storage_encrypted    = true
  kms_key_id           = aws_kms_key.kms-rds.arn
  # master_user_secret_kms_key_id = "${aws_kms_key.kms-rds.key_id}"
  # master_user_secret{
  #   kms_key_id = "arn:aws:kms:us-east-1:083968887191:key/3952c524-c5f3-4b77-be35-c4ce0a5bf60a"
  # }


  tags = {
    "Name" = "rds-${timestamp()}"
  }
}

resource "random_string" "s3_bucket_name" {
  length  = 10
  special = false
  lower   = true
}
resource "random_uuid" "uuid" {}

#Create a S3 bucket
resource "aws_s3_bucket" "s3_bucket" {
  # bucket        = "s3_bucket_mansi_${random_string.s3_bucket_name.result}"
  bucket        = "my-s3-bucket-${random_uuid.uuid.result}"
  force_destroy = true
  # aws_s3_bucket_acl = "private"

  tags = {
    "Name" = "s3_bucket-${timestamp()}"
  }
}

resource "aws_s3_bucket_acl" "bucket_acl" {
  bucket = aws_s3_bucket.s3_bucket.id
  acl    = "private"
}

# Define the lifecycle policy
resource "aws_s3_bucket_lifecycle_configuration" "S3_lifecycle" {
  rule {
    id     = "example_rule"
    status = "Enabled"

    # Transition objects to STANDARD_IA storage class after 30 days
    transition {
      days          = 30
      storage_class = var.storage_class
    }

    # Expire objects after 60 days
    expiration {
      days = 60
    }

    # Filter the rule to apply to all objects in the bucket
    filter {
      prefix = ""
    }
  }

  # Associate the lifecycle policy with the S3 bucket
  lifecycle {
    ignore_changes = [
      rule,
    ]

    # Run the lifecycle policy every day
    prevent_destroy = false
  }

  bucket = aws_s3_bucket.s3_bucket.id
}


#Default encryption for s3 bucket 
resource "aws_s3_bucket_server_side_encryption_configuration" "s3_default_encryption" {
  bucket = aws_s3_bucket.s3_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = var.sse_algorithm
    }
  }
}

#Create IAM Role
resource "aws_iam_role" "EC2-CSYE6225_role" {
  name               = "EC2-CSYE6225"
  assume_role_policy = file("assumerolepolicy.json")
}

#Create IAM Policy
resource "aws_iam_policy" "WebAppS3_policy" {
  name        = "WebAppS3"
  description = "A IAM policy"
  #   policy      = "${file("policys3bucket.json")}"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          # "s3:*"
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:PutObjectAcl",
          "s3:GetObjectAcl"

        ],
        "Effect" : "Allow",
        "Resource" : [
          "${aws_s3_bucket.s3_bucket.arn}",
          "${aws_s3_bucket.s3_bucket.arn}/*"
        ],

      }
    ]

  })
}

#Attaching Policy to the role
resource "aws_iam_policy_attachment" "S3-policy-attach" {
  name       = var.S3-policy-attach
  roles      = ["${aws_iam_role.EC2-CSYE6225_role.name}"]
  policy_arn = aws_iam_policy.WebAppS3_policy.arn
}

resource "aws_iam_policy_attachment" "webapp-attach-cloudwatch" {
  name       = "attach-cloudwatch"
  roles      = ["${aws_iam_role.EC2-CSYE6225_role.name}"]
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}


#IAM instance profile
resource "aws_iam_instance_profile" "instance_profile" {
  name = var.instance_profile
  role = aws_iam_role.EC2-CSYE6225_role.name
}

resource "aws_route53_record" "record" {
  zone_id = var.zone_id
  name    = ""
  type    = "A"
  # ttl     = 60
  alias {
    name                   = aws_lb.lb.dns_name
    zone_id                = aws_lb.lb.zone_id
    evaluate_target_health = true
  }
}

#User data
data "template_file" "user_data" {

  template = <<EOF

#!/bin/bash

sudo sed -i 's/HOST: "localhost"/HOST: "${aws_db_instance.rds_instance.address}"/g' /home/ec2-user/webApp/config/db.config.js
sudo sed -i 's/USER: "postgres"/USER: "${var.database_username}"/g' /home/ec2-user/webApp/config/db.config.js
sudo sed -i 's/PASSWORD: "M@nsi2875"/PASSWORD: "${var.database_password}"/g' /home/ec2-user/webApp/config/db.config.js
sudo sed -i 's/s3_bucket_name:"my-s3-bucket-3beb24c7-be10-0b55-4dd0-699f0b7336fb"/s3_bucket_name: "${aws_s3_bucket.s3_bucket.bucket}"/g' /home/ec2-user/webApp/config/db.config.js
cd /home/ec2-user/webApp/
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/home/ec2-user/webApp/cloud-watch.json -s    
sudo pm2 start server.js
sudo pm2 startup
sudo pm2 save
sudo pm2 restart server.js
  EOF

}

#Autoscaling for EC2 Instances
resource "aws_launch_template" "lt" {

  name          = var.aws_launch_template_name
  user_data     = base64encode(data.template_file.user_data.rendered)
  image_id      = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_name
  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.application.id]
  }
  iam_instance_profile {
    name = aws_iam_instance_profile.instance_profile.name
  }

  block_device_mappings {

    device_name = var.device_name
    ebs {
      volume_size           = var.volume_size
      volume_type           = var.volume_type
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = aws_kms_key.kms-ec2.arn
      # kms_key_id = "arn:aws:kms:us-east-1:083968887191:key/0e4a985c-5de2-403b-b509-19167d06274e"
    }

  }
}


#Autoscaling group
resource "aws_autoscaling_group" "asg" {

  name             = var.asg_name
  default_cooldown = 60
  # launch_configuration = "asg_launch_config"
  min_size            = 1
  max_size            = 3
  desired_capacity    = 1
  vpc_zone_identifier = [aws_subnet.subnet-public-1.id, aws_subnet.subnet-public-2.id]
  # vpc_security_group_ids = [aws_security_group.application.id]
  tag {
    key                 = "Application"
    value               = "webApp"
    propagate_at_launch = true
  }

  launch_template {
    id      = aws_launch_template.lt.id
    version = "$Latest"
  }

  target_group_arns = [aws_lb_target_group.alb_tg.arn]
}

#Autoscaling policies - Scale up
resource "aws_autoscaling_policy" "scale_up_policy" {
  name                   = var.aws_autoscaling_policy_up_name
  policy_type            = var.policy_type
  scaling_adjustment     = var.scaling_adjustment_up
  autoscaling_group_name = aws_autoscaling_group.asg.name
  adjustment_type        = var.adjustment_type
  cooldown               = 60
}

#Autoscaling policies - Scale down
resource "aws_autoscaling_policy" "scale_down_policy" {
  name                   = var.aws_autoscaling_policy_down_name
  policy_type            = var.policy_type
  scaling_adjustment     = var.scaling_adjustment_down
  autoscaling_group_name = aws_autoscaling_group.asg.name
  adjustment_type        = var.adjustment_type
  cooldown               = 60
}

#Alarm for Scale up
resource "aws_cloudwatch_metric_alarm" "alarm_scale_up" {
  alarm_name          = var.alarm_name_up
  comparison_operator = var.comparison_operator_up
  evaluation_periods  = 2
  metric_name         = var.metric_name
  namespace           = var.namespace
  period              = 120
  statistic           = var.statistic
  threshold           = 5
  alarm_description   = var.alarm_description
  dimensions = {
    "AutoScalingGroupName" = aws_autoscaling_group.asg.name
  }
  actions_enabled = true
  alarm_actions   = [aws_autoscaling_policy.scale_up_policy.arn]
}

#Alarm for  scale down
resource "aws_cloudwatch_metric_alarm" "alarm_scale_down" {

  alarm_name          = var.alarm_name_down
  comparison_operator = var.comparison_operator_down
  evaluation_periods  = 2
  metric_name         = var.metric_name
  namespace           = var.namespace
  period              = 120
  statistic           = var.statistic
  threshold           = 3
  alarm_description   = var.alarm_description
  # insufficient_data_actions = []
  dimensions = {
    "AutoScalingGroupName" = aws_autoscaling_group.asg.name
  }
  actions_enabled = true
  alarm_actions   = [aws_autoscaling_policy.scale_down_policy.arn]
}

#Application Load Balancer
resource "aws_lb" "lb" {


  name               = var.aws_lb_name
  internal           = false
  load_balancer_type = var.load_balancer_type
  tags = {
    Application = "WebApp"
  }
  security_groups = [aws_security_group.load_balancer.id]
  subnets = [
    aws_subnet.subnet-public-1.id,
    aws_subnet.subnet-public-2.id,
    aws_subnet.subnet-public-3.id
  ]
}

#Load balancer target group
resource "aws_lb_target_group" "alb_tg" {
  name        = var.aws_lb_target_group_name
  target_type = var.target_type
  port        = "8080"
  protocol    = "HTTP"
  vpc_id      = aws_vpc.myvpc.id
  health_check {
    # protocol = "HTTP"
    interval = 30
    timeout  = 10
    matcher  = "200"
    path     = "/healthz"
  }

}

#Load balancer Listener
resource "aws_lb_listener" "front_end" {

  load_balancer_arn = aws_lb.lb.arn
  port              = "443"   #
  protocol          = "HTTPS" #
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.alb_tg.arn
  }

}