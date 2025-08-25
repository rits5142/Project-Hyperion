terraform {
  required_version = ">= 1.3.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.100.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# Resource Group
resource "azurerm_resource_group" "spoke_rg" {
  name     = "AzureRG"
  location = "malaysiawest"
  tags     = var.tags
}

# Virtual Network (Spoke)
resource "azurerm_virtual_network" "spoke_vnet" {
  name                = "${var.name_prefix}-spoke-vnet"
  address_space       = [var.vnet_cidr]
  location            = azurerm_resource_group.spoke_rg.location
  resource_group_name = azurerm_resource_group.spoke_rg.name
  tags                = var.tags
}

# Subnets
resource "azurerm_subnet" "spoke_subnets" {
  for_each = var.subnets
  name                 = each.key
  address_prefixes     = [each.value]
  resource_group_name  = azurerm_resource_group.spoke_rg.name
  virtual_network_name = azurerm_virtual_network.spoke_vnet.name
}
