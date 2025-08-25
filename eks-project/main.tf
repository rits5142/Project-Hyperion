module "eks" {
  source          = "terraform-aws-modules/eks/aws"
  version         = "20.24.0"

  cluster_name    = var.cluster_name
  cluster_version = "1.29"

  vpc_id          = var.vpc_id
  subnet_ids      = var.subnet_ids

  enable_irsa     = true

  eks_managed_node_groups = {
    default = {
      instance_types = ["t3.micro"]
      min_size       = 1
      max_size       = 3
      desired_size   = 2
    }
  }
}
