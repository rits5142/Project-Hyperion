output "vnet_id" {
  description = "The ID of the created Virtual Network"
  value       = azurerm_virtual_network.spoke_vnet.id
}

output "subnet_ids" {
  description = "The IDs of the created subnets"
  value       = { for k, s in azurerm_subnet.spoke_subnets : k => s.id }
}
