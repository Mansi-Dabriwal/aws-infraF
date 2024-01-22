Terraform Commands to setup VPC, Subnets, Route Table and Internet Gateway

terraform init: This command initializes a working directory containing Terraform configuration files. This is the first command that should be run after writing a new Terraform configuration

terraform plan: This command creates an execution plan, which lets you preview the changes that Terraform plans to make to your infrastructure. Since we've created two AWS profile i.e dev and demo, we need to add '-var-file' name that needs to be executed by this command. For example: For dev file - terraform plan -var-file=dev.tfvars and for the demo file - terraform plan -var-file=demo.tfvars

terraform apply: This command executes the actions proposed in a Terraform plan.

terraform destroy: This command is a convenient way to destroy all remote objects managed by a particular Terraform configuration.

Add SSL certificate to AWS console by using this command - aws acm import-certificate --profile demo --region us-east-1 --certificate file://xxxx.crt --private-key file://private.key --certificate-chain file://xxxxx-bundle
