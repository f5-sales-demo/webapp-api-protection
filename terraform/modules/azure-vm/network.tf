resource "azurerm_virtual_network" "main" {
  name                = local.name.virtual_network
  address_space       = var.address_space
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = azurerm_resource_group.main.tags
}

resource "azurerm_subnet" "main" {
  #checkov:skip=CKV2_AZURE_31:Lab subnet - NSG associated at NIC level
  name                 = local.name.subnet
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = var.subnet_prefixes
}

resource "azurerm_public_ip" "main" {
  name                = local.name.public_ip
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = azurerm_resource_group.main.tags
}

resource "azurerm_network_security_group" "main" {
  #checkov:skip=CKV_AZURE_10:Lab NSG - SSH open for demo access
  #checkov:skip=CKV_AZURE_160:Lab NSG - HTTP port 80 required for traffic
  #checkov:skip=CKV_AZURE_220:Lab NSG - SSH open for demo access
  name                = local.name.nsg
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  dynamic "security_rule" {
    for_each = var.security_rules
    content {
      name                       = security_rule.value.name
      priority                   = security_rule.value.priority
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = security_rule.value.port
      source_address_prefix      = "*"
      destination_address_prefix = "*"
    }
  }

  tags = azurerm_resource_group.main.tags
}

resource "azurerm_network_interface" "main" {
  #checkov:skip=CKV_AZURE_119:Lab NIC - public IP required for demo access
  name                = local.name.network_interface
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.main.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.main.id
  }

  tags = azurerm_resource_group.main.tags
}

resource "azurerm_network_interface_security_group_association" "main" {
  network_interface_id      = azurerm_network_interface.main.id
  network_security_group_id = azurerm_network_security_group.main.id
}
