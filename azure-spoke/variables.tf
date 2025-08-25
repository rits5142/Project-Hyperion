variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "demo"
}

variable "vnet_cidr" {
  description = "CIDR block for VNet"
  type        = string
  default     = "10.10.0.0/16"
}

variable "subnets" {
  description = "Map of subnet names to CIDR blocks"
  type        = map(string)
  default = {
    app     = "10.10.1.0/24"
    backend = "10.10.2.0/24"
  }
}

variable "tags" {
  description = "Common resource tags"
  type        = map(string)
  default = {
    environment = "dev"
    owner       = "network-team"
  }
}
