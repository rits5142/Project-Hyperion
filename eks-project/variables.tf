variable "cluster_name" {
  default = "eks-cluster"
}

variable "vpc_id" {
  default = "vpc-0a582bb63d83d8ea2"
}

variable "subnet_ids" {
  default = [
    "subnet-04734036e18c5fa12",
    "subnet-02423c39e8ad36121",
    "subnet-0979edf9152ce7a0e"
  ]
}
