region                = "us-east-1"
cidr_block_vpc        = "10.0.0.0/16"
env                   = "dev"
subnet_public_name_1  = "dev-public-1"
subnet_public_name_2  = "dev-public-2"
subnet_public_name_3  = "dev-public-3"
subnet_private_name_1 = "dev-private-1"
subnet_private_name_2 = "dev-private-2"
subnet_private_name_3 = "dev-private-3"
cidr_subnet_3         = "10.0.3.0/24"
cidr_subnet_2         = "10.0.2.0/24"
cidr_subnet_1         = "10.0.1.0/24"
cidr_subnet_4         = "10.0.4.0/24"
cidr_subnet_5         = "10.0.5.0/24"
cidr_subnet_6         = "10.0.6.0/24"
cidr_ig               = "0.0.0.0/0"
public_launch         = "true"
private_launch        = "false"
ami_id                = "ami-08f724afd520a3083"
instance_profile      = "dev_instance_profile"
S3-policy-attach      = "dev_S3-policy-attach"
instance_type         = "t2.micro"
volume_size           = 50
volume_type           = "gp2"
device_name           = "/dev/xvda"
engine                = "postgres"
engine_version        = 13.7
instance_class        = "db.t3.micro"
db_name               = "csye6225"
username              = "csye6225"
password              = "Mansi2875"
storage_class         = "STANDARD_IA"
allocated_storage     = 10
identifier            = "app-rds-db"
zone_id               = "Z0391061IPKHQ28MO7HI"
route_53_name         = "dev4.dabriwalm.me"