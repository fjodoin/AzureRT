#!/usr/bin/env python3
"""
Enhanced Azure Resource Collector

A standalone script that collects Azure resources and their relationships,
inspired by Stormspotter's stormcollector.
Note: EntraID resources (formerly Azure AD/AAD) are collected using Microsoft Graph.
"""

import argparse
import csv
import datetime
import json
import logging
import os
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional, Set

import requests

# Azure SDK imports
try:
    from azure.common.credentials import get_azure_cli_credentials
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.resource.subscriptions import SubscriptionClient
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.keyvault import KeyVaultManagementClient
    from azure.mgmt.web import WebSiteManagementClient
    from azure.mgmt.msi import ManagedServiceIdentityClient
    from azure.mgmt.containerservice import ContainerServiceClient
    from azure.mgmt.automation import AutomationClient
    from azure.mgmt.cosmosdb import CosmosDBManagementClient
    from azure.mgmt.sql import SqlManagementClient
    from azure.mgmt.logic import LogicManagementClient
    from azure.mgmt.datafactory import DataFactoryManagementClient
    from azure.identity import DefaultAzureCredential, ClientSecretCredential
    from msrestazure.azure_exceptions import CloudError
except ImportError:
    print("Required Azure SDK packages not found. Installing...")
    import subprocess
    packages = [
        "azure-common",
        "azure-mgmt-resource",
        "azure-mgmt-authorization",
        "azure-mgmt-compute",
        "azure-mgmt-network",
        "azure-mgmt-storage",
        "azure-mgmt-keyvault",
        "azure-mgmt-web",
        "azure-mgmt-msi",
        "azure-mgmt-containerservice",
        "azure-mgmt-automation",
        "azure-mgmt-cosmosdb",
        "azure-mgmt-sql",
        "azure-mgmt-logic",
        "azure-mgmt-datafactory",
        "azure-identity",
        "msrestazure"
    ]
    subprocess.check_call([sys.executable, "-m", "pip", "install"] + packages)
    
    # Retry imports
    from azure.common.credentials import get_azure_cli_credentials
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.resource.subscriptions import SubscriptionClient
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.keyvault import KeyVaultManagementClient
    from azure.mgmt.web import WebSiteManagementClient
    from azure.mgmt.msi import ManagedServiceIdentityClient
    from azure.mgmt.containerservice import ContainerServiceClient
    from azure.mgmt.automation import AutomationClient
    from azure.mgmt.cosmosdb import CosmosDBManagementClient
    from azure.mgmt.sql import SqlManagementClient
    from azure.mgmt.logic import LogicManagementClient
    from azure.mgmt.datafactory import DataFactoryManagementClient
    from azure.identity import DefaultAzureCredential, ClientSecretCredential
    from msrestazure.azure_exceptions import CloudError

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("AzureCollector")


class AzureCollector:
    """
    Main collector class that orchestrates the collection of Azure resources.
    """
    
    def __init__(self, output_dir: str = "azure_data", tenant_id: str = None):
        """
        Initialize the Azure collector.
        
        Args:
            output_dir: Directory to store collected data.
            tenant_id: Azure tenant ID to collect from (optional).
        """
        self.output_dir = output_dir
        self.tenant_id = tenant_id
        self.collected_data = {
            "subscriptions": [],
            "resource_groups": [],
            "virtual_machines": [],
            "virtual_machine_scale_sets": [],
            "network_interfaces": [],
            "virtual_networks": [],
            "subnets": [],
            "network_security_groups": [],
            "public_ips": [],
            "storage_accounts": [],
            "key_vaults": [],
            "app_services": [],
            "user_assigned_identities": [],
            "system_assigned_identities": [],
            "aks_clusters": [],
            "automation_accounts": [],
            "cosmos_db_accounts": [],
            "sql_servers": [],
            "logic_apps": [],
            "data_factories": [],
            "rbac_assignments": [],
            "rbac_definitions": [],
            "entra_id_users": [],
            "entra_id_groups": [],
            "entra_id_service_principals": []
        }
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Set up Azure credentials
        self._setup_credentials()
    
    def _setup_credentials(self):
        """Set up Azure credentials for API calls."""
        try:
            # Try to get credentials from Azure CLI first
            credentials_tuple = get_azure_cli_credentials(with_tenant=True)
            self.credentials = credentials_tuple[0]
            self.subscription_id = credentials_tuple[1]
            self.tenant_id = self.tenant_id or credentials_tuple[2]  # Fixed: Access tenant_id from tuple
            logger.info(f"Using Azure CLI credentials for tenant {self.tenant_id}")
        except Exception as e:
            # Fall back to DefaultAzureCredential
            logger.info(f"Azure CLI credentials not available, using DefaultAzureCredential: {str(e)}")
            self.credentials = DefaultAzureCredential()
            self.tenant_id = self.tenant_id or os.environ.get("AZURE_TENANT_ID")
            if not self.tenant_id:
                logger.error("No tenant ID found. Please specify using --tenant-id or set AZURE_TENANT_ID environment variable")
                sys.exit(1)
        
        # Initialize subscription client
        self.subscription_client = SubscriptionClient(self.credentials)
    
    def _graph_api_get_all(self, url: str, headers: dict) -> list:
        """
        Helper method to page through Microsoft Graph API results.
        """
        items = []
        while url:
            try:
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()
                items.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
            except Exception as e:
                logger.error(f"Error fetching data from Microsoft Graph API ({url}): {str(e)}")
                if hasattr(response, 'text'):
                    logger.error(f"Response text: {response.text}")
                break
        return items

    def collect_all(self, collect_entraid=False):
        """Collect all Azure resources."""
        logger.info("Starting Azure resource collection")
        
        # Collect subscriptions first
        subscriptions = self.collect_subscriptions()
        if not subscriptions:
            logger.error("No subscriptions found or accessible")
            return
        
        # Collect resources for each subscription concurrently
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self.collect_subscription_resources, sub["id"]) for sub in subscriptions]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error collecting subscription resources: {str(e)}")
        
        # Collect EntraID resources if requested
        if collect_entraid:
            logger.info("Starting EntraID resource collection")
            self.collect_entraid()
        
        # Save all collected data to CSV files
        self._save_results_csv()
        logger.info(f"Collection complete. CSV files saved to {self.output_dir}")

    def collect_subscriptions(self) -> List[Dict]:
        """Collect all accessible subscriptions."""
        logger.info("Collecting subscriptions")
        subscriptions = []
        
        try:
            for sub in self.subscription_client.subscriptions.list():
                sub_data = {
                    "id": sub.subscription_id,
                    "name": sub.display_name,
                    "state": sub.state,
                    "tenant_id": self.tenant_id
                }
                subscriptions.append(sub_data)
                self.collected_data["subscriptions"].append(sub_data)
                logger.info(f"Found subscription: {sub.display_name} ({sub.subscription_id})")
        except Exception as e:
            logger.error(f"Error collecting subscriptions: {str(e)}")
        
        return subscriptions

    def collect_subscription_resources(self, subscription_id: str):
        """Collect all resources for a specific subscription."""
        logger.info(f"Collecting resources for subscription {subscription_id}")
        
        # Create clients for this subscription
        resource_client = ResourceManagementClient(self.credentials, subscription_id)
        compute_client = ComputeManagementClient(self.credentials, subscription_id)
        network_client = NetworkManagementClient(self.credentials, subscription_id)
        storage_client = StorageManagementClient(self.credentials, subscription_id)
        keyvault_client = KeyVaultManagementClient(self.credentials, subscription_id)
        web_client = WebSiteManagementClient(self.credentials, subscription_id)
        msi_client = ManagedServiceIdentityClient(self.credentials, subscription_id)
        aks_client = ContainerServiceClient(self.credentials, subscription_id)
        automation_client = AutomationClient(self.credentials, subscription_id)
        cosmosdb_client = CosmosDBManagementClient(self.credentials, subscription_id)
        sql_client = SqlManagementClient(self.credentials, subscription_id)
        logic_client = LogicManagementClient(self.credentials, subscription_id)
        datafactory_client = DataFactoryManagementClient(self.credentials, subscription_id)
        auth_client = AuthorizationManagementClient(self.credentials, subscription_id)
        
        # Collect resource groups
        self._collect_resource_groups(resource_client, subscription_id)
        
        # Collect compute resources
        self._collect_virtual_machines(compute_client, subscription_id)
        self._collect_virtual_machine_scale_sets(compute_client, subscription_id)
        
        # Collect network resources
        self._collect_network_resources(network_client, subscription_id)
        
        # Collect storage accounts
        self._collect_storage_accounts(storage_client, subscription_id)
        
        # Collect key vaults - Fixed implementation
        self._collect_key_vaults_fixed(keyvault_client, subscription_id)
        
        # Collect app services (Web/Sites)
        self._collect_app_services(web_client, subscription_id)
        
        # Collect managed identities
        self._collect_user_assigned_identities(msi_client, subscription_id)
        
        # Collect AKS clusters
        self._collect_aks_clusters(aks_client, subscription_id)
        
        # Collect automation accounts
        self._collect_automation_accounts(automation_client, subscription_id)
        
        # Collect Cosmos DB accounts
        self._collect_cosmos_db_accounts(cosmosdb_client, subscription_id)
        
        # Collect SQL servers
        self._collect_sql_servers(sql_client, subscription_id)
        
        # Collect Logic Apps
        self._collect_logic_apps(logic_client, subscription_id)
        
        # Collect Data Factories
        self._collect_data_factories(datafactory_client, subscription_id)
        
        # Collect RBAC assignments
        self._collect_rbac_assignments(auth_client, subscription_id)
        
        # Collect RBAC role definitions
        self._collect_rbac_definitions(auth_client, subscription_id)

    def _collect_resource_groups(self, client: ResourceManagementClient, subscription_id: str):
        """Collect all resource groups in the subscription."""
        logger.info(f"Collecting resource groups for subscription {subscription_id}")
        
        try:
            for rg in client.resource_groups.list():
                rg_data = {
                    "id": rg.id,
                    "name": rg.name,
                    "location": rg.location,
                    "subscription_id": subscription_id,
                    "tags": json.dumps(rg.tags or {})  # Convert dict to JSON string for CSV
                }
                self.collected_data["resource_groups"].append(rg_data)
                logger.debug(f"Collected resource group: {rg.name}")
        except Exception as e:
            logger.error(f"Error collecting resource groups: {str(e)}")

    def _collect_virtual_machines(self, client: ComputeManagementClient, subscription_id: str):
        """Collect all virtual machines in the subscription."""
        logger.info(f"Collecting virtual machines for subscription {subscription_id}")
        
        try:
            for vm in client.virtual_machines.list_all():
                vm_data = {
                    "id": vm.id,
                    "name": vm.name,
                    "resource_group": self._extract_resource_group(vm.id),
                    "subscription_id": subscription_id,
                    "location": vm.location,
                    "vm_size": vm.hardware_profile.vm_size,
                    "os_type": vm.storage_profile.os_disk.os_type,
                    "os_disk": vm.storage_profile.os_disk.name,
                    "admin_username": getattr(vm.os_profile, 'admin_username', None) if hasattr(vm, 'os_profile') else None,
                    "network_interfaces": json.dumps([nic.id for nic in vm.network_profile.network_interfaces]) if vm.network_profile else "[]",
                    "tags": json.dumps(vm.tags or {})
                }
                
                # Check for system-assigned managed identity
                if hasattr(vm, 'identity') and vm.identity:
                    vm_data["identity_type"] = vm.identity.type
                    if vm.identity.type in ['SystemAssigned', 'SystemAssigned, UserAssigned']:
                        self._collect_system_assigned_identity(vm, subscription_id)
                    
                    if vm.identity.type in ['UserAssigned', 'SystemAssigned, UserAssigned']:
                        vm_data["user_assigned_identities"] = json.dumps(list(vm.identity.user_assigned_identities.keys()) if vm.identity.user_assigned_identities else [])
                
                self.collected_data["virtual_machines"].append(vm_data)
                logger.debug(f"Collected VM: {vm.name}")
        except Exception as e:
            logger.error(f"Error collecting virtual machines: {str(e)}")

    def _collect_virtual_machine_scale_sets(self, client: ComputeManagementClient, subscription_id: str):
        """Collect all virtual machine scale sets in the subscription."""
        logger.info(f"Collecting virtual machine scale sets for subscription {subscription_id}")
        
        try:
            for vmss in client.virtual_machine_scale_sets.list_all():
                vmss_data = {
                    "id": vmss.id,
                    "name": vmss.name,
                    "resource_group": self._extract_resource_group(vmss.id),
                    "subscription_id": subscription_id,
                    "location": vmss.location,
                    "vm_size": vmss.sku.name,
                    "capacity": vmss.sku.capacity,
                    "os_type": "Windows" if vmss.virtual_machine_profile.storage_profile.os_disk.os_type == "Windows" else "Linux",
                    "upgrade_policy": vmss.upgrade_policy.mode,
                    "single_placement_group": vmss.single_placement_group,
                    "tags": json.dumps(vmss.tags or {})
                }
                
                # Check for system-assigned managed identity
                if hasattr(vmss, 'identity') and vmss.identity:
                    vmss_data["identity_type"] = vmss.identity.type
                    if vmss.identity.type in ['SystemAssigned', 'SystemAssigned, UserAssigned']:
                        self._collect_system_assigned_identity(vmss, subscription_id)
                    
                    if vmss.identity.type in ['UserAssigned', 'SystemAssigned, UserAssigned']:
                        vmss_data["user_assigned_identities"] = json.dumps(list(vmss.identity.user_assigned_identities.keys()) if vmss.identity.user_assigned_identities else [])
                
                self.collected_data["virtual_machine_scale_sets"].append(vmss_data)
                logger.debug(f"Collected VMSS: {vmss.name}")
        except Exception as e:
            logger.error(f"Error collecting virtual machine scale sets: {str(e)}")

    def _collect_network_resources(self, client: NetworkManagementClient, subscription_id: str):
        """Collect all network resources in the subscription."""
        logger.info(f"Collecting network resources for subscription {subscription_id}")
        
        # Collect network interfaces
        try:
            for nic in client.network_interfaces.list_all():
                nic_data = {
                    "id": nic.id,
                    "name": nic.name,
                    "resource_group": self._extract_resource_group(nic.id),
                    "subscription_id": subscription_id,
                    "location": nic.location,
                    "ip_configurations": json.dumps([{
                        "name": ip_config.name,
                        "private_ip": ip_config.private_ip_address,
                        "private_ip_allocation": ip_config.private_ip_allocation_method,
                        "public_ip": ip_config.public_ip_address.id if ip_config.public_ip_address else None,
                        "subnet": ip_config.subnet.id if ip_config.subnet else None
                    } for ip_config in nic.ip_configurations]),
                    "nsg": nic.network_security_group.id if nic.network_security_group else None,
                    "tags": json.dumps(nic.tags or {})
                }
                self.collected_data["network_interfaces"].append(nic_data)
                logger.debug(f"Collected NIC: {nic.name}")
        except Exception as e:
            logger.error(f"Error collecting network interfaces: {str(e)}")
        
        # Collect virtual networks and subnets
        try:
            for vnet in client.virtual_networks.list_all():
                vnet_data = {
                    "id": vnet.id,
                    "name": vnet.name,
                    "resource_group": self._extract_resource_group(vnet.id),
                    "subscription_id": subscription_id,
                    "location": vnet.location,
                    "address_space": json.dumps(vnet.address_space.address_prefixes if vnet.address_space else []),
                    "subnets": json.dumps([subnet.id for subnet in vnet.subnets]) if vnet.subnets else "[]",
                    "tags": json.dumps(vnet.tags or {})
                }
                self.collected_data["virtual_networks"].append(vnet_data)
                logger.debug(f"Collected VNet: {vnet.name}")
                
                # Collect subnets
                for subnet in vnet.subnets:
                    subnet_data = {
                        "id": subnet.id,
                        "name": subnet.name,
                        "vnet_id": vnet.id,
                        "resource_group": self._extract_resource_group(subnet.id),
                        "subscription_id": subscription_id,
                        "address_prefix": subnet.address_prefix,
                        "nsg": subnet.network_security_group.id if subnet.network_security_group else None
                    }
                    self.collected_data["subnets"].append(subnet_data)
                    logger.debug(f"Collected Subnet: {subnet.name}")
        except Exception as e:
            logger.error(f"Error collecting virtual networks and subnets: {str(e)}")
        
        # Collect network security groups
        try:
            for nsg in client.network_security_groups.list_all():
                nsg_data = {
                    "id": nsg.id,
                    "name": nsg.name,
                    "resource_group": self._extract_resource_group(nsg.id),
                    "subscription_id": subscription_id,
                    "location": nsg.location,
                    "security_rules": json.dumps([{
                        "name": rule.name,
                        "description": rule.description,
                        "protocol": rule.protocol,
                        "source_port_range": rule.source_port_range,
                        "destination_port_range": rule.destination_port_range,
                        "source_address_prefix": rule.source_address_prefix,
                        "destination_address_prefix": rule.destination_address_prefix,
                        "access": rule.access,
                        "priority": rule.priority,
                        "direction": rule.direction
                    } for rule in nsg.security_rules]) if nsg.security_rules else "[]",
                    "tags": json.dumps(nsg.tags or {})
                }
                self.collected_data["network_security_groups"].append(nsg_data)
                logger.debug(f"Collected NSG: {nsg.name}")
        except Exception as e:
            logger.error(f"Error collecting network security groups: {str(e)}")
        
        # Collect public IP addresses
        try:
            for pip in client.public_ip_addresses.list_all():
                pip_data = {
                    "id": pip.id,
                    "name": pip.name,
                    "resource_group": self._extract_resource_group(pip.id),
                    "subscription_id": subscription_id,
                    "location": pip.location,
                    "ip_address": pip.ip_address,
                    "allocation_method": pip.public_ip_allocation_method,
                    "tags": json.dumps(pip.tags or {})
                }
                self.collected_data["public_ips"].append(pip_data)
                logger.debug(f"Collected Public IP: {pip.name}")
        except Exception as e:
            logger.error(f"Error collecting public IP addresses: {str(e)}")

    def _collect_storage_accounts(self, client: StorageManagementClient, subscription_id: str):
        """Collect all storage accounts in the subscription."""
        logger.info(f"Collecting storage accounts for subscription {subscription_id}")
        
        try:
            for sa in client.storage_accounts.list():
                sa_data = {
                    "id": sa.id,
                    "name": sa.name,
                    "resource_group": self._extract_resource_group(sa.id),
                    "subscription_id": subscription_id,
                    "location": sa.location,
                    "sku": sa.sku.name,
                    "kind": sa.kind,
                    "https_only": sa.enable_https_traffic_only,
                    "access_tier": sa.access_tier,
                    "tags": json.dumps(sa.tags or {})
                }
                
                # Check for system-assigned managed identity
                if hasattr(sa, 'identity') and sa.identity:
                    sa_data["identity_type"] = sa.identity.type
                    if sa.identity.type in ['SystemAssigned', 'SystemAssigned, UserAssigned']:
                        self._collect_system_assigned_identity(sa, subscription_id)
                    
                    if sa.identity.type in ['UserAssigned', 'SystemAssigned, UserAssigned']:
                        sa_data["user_assigned_identities"] = json.dumps(list(sa.identity.user_assigned_identities.keys()) if sa.identity.user_assigned_identities else [])
                
                self.collected_data["storage_accounts"].append(sa_data)
                logger.debug(f"Collected Storage Account: {sa.name}")
        except Exception as e:
            logger.error(f"Error collecting storage accounts: {str(e)}")

    def _collect_key_vaults_fixed(self, client: KeyVaultManagementClient, subscription_id: str):
        """
        Collect all key vaults in the subscription - Fixed implementation.
        The original code had issues with accessing vault properties.
        """
        logger.info(f"Collecting key vaults for subscription {subscription_id}")
        
        try:
            # First, list all key vaults in the subscription
            vaults = list(client.vaults.list())
            logger.info(f"Found {len(vaults)} key vaults in subscription {subscription_id}")
            
            # Then, get detailed information for each vault
            for vault in vaults:
                try:
                    resource_group_name = self._extract_resource_group(vault.id)
                    vault_name = vault.name
                    
                    # Get detailed vault information
                    vault_detail = client.vaults.get(resource_group_name, vault_name)
                    
                    vault_data = {
                        "id": vault_detail.id,
                        "name": vault_detail.name,
                        "resource_group": resource_group_name,
                        "subscription_id": subscription_id,
                        "location": vault_detail.location,
                        "tenant_id": vault_detail.properties.tenant_id,
                        "sku": vault_detail.properties.sku.name,
                        "vault_uri": vault_detail.properties.vault_uri,
                        "enabled_for_deployment": vault_detail.properties.enabled_for_deployment,
                        "enabled_for_disk_encryption": vault_detail.properties.enabled_for_disk_encryption,
                        "enabled_for_template_deployment": vault_detail.properties.enabled_for_template_deployment,
                        "soft_delete_enabled": getattr(vault_detail.properties, 'soft_delete_enabled', None),
                        "purge_protection_enabled": getattr(vault_detail.properties, 'purge_protection_enabled', None),
                        "tags": json.dumps(vault_detail.tags or {})
                    }
                    
                    # Process access policies
                    if vault_detail.properties.access_policies:
                        policies = []
                        for policy in vault_detail.properties.access_policies:
                            policy_data = {
                                "tenant_id": policy.tenant_id,
                                "object_id": policy.object_id,
                                "permissions": {
                                    "keys": policy.permissions.keys or [] if hasattr(policy.permissions, 'keys') else [],
                                    "secrets": policy.permissions.secrets or [] if hasattr(policy.permissions, 'secrets') else [],
                                    "certificates": policy.permissions.certificates or [] if hasattr(policy.permissions, 'certificates') else [],
                                    "storage": policy.permissions.storage or [] if hasattr(policy.permissions, 'storage') else []
                                }
                            }
                            policies.append(policy_data)
                        vault_data["access_policies"] = json.dumps(policies)
                    else:
                        vault_data["access_policies"] = "[]"
                    
                    # Check for system-assigned managed identity
                    if hasattr(vault_detail, 'identity') and vault_detail.identity:
                        vault_data["identity_type"] = vault_detail.identity.type
                        if vault_detail.identity.type in ['SystemAssigned', 'SystemAssigned, UserAssigned']:
                            self._collect_system_assigned_identity(vault_detail, subscription_id)
                        
                        if vault_detail.identity.type in ['UserAssigned', 'SystemAssigned, UserAssigned']:
                            vault_data["user_assigned_identities"] = json.dumps(list(vault_detail.identity.user_assigned_identities.keys()) if vault_detail.identity.user_assigned_identities else [])
                    
                    self.collected_data["key_vaults"].append(vault_data)
                    logger.debug(f"Collected Key Vault: {vault_name}")
                    
                except Exception as kv_error:
                    logger.error(f"Error processing key vault {vault.name}: {str(kv_error)}")
        except Exception as e:
            logger.error(f"Error collecting key vaults: {str(e)}")

    def _collect_app_services(self, client: WebSiteManagementClient, subscription_id: str):
        """Collect all App Services (Web/Sites) in the subscription."""
        logger.info(f"Collecting App Services for subscription {subscription_id}")
        
        try:
            for site in client.web_apps.list():
                site_data = {
                    "id": site.id,
                    "name": site.name,
                    "resource_group": self._extract_resource_group(site.id),
                    "subscription_id": subscription_id,
                    "location": site.location,
                    "kind": site.kind,
                    "state": site.state,
                    "enabled": site.enabled,
                    "host_names": json.dumps(site.host_names or []),
                    "default_host_name": site.default_host_name,
                    "outbound_ip_addresses": site.outbound_ip_addresses,
                    "tags": json.dumps(site.tags or {})
                }
                
                # Check for system-assigned managed identity
                if hasattr(site, 'identity') and site.identity:
                    site_data["identity_type"] = site.identity.type
                    if site.identity.type in ['SystemAssigned', 'SystemAssigned, UserAssigned']:
                        self._collect_system_assigned_identity(site, subscription_id)
                    
                    if site.identity.type in ['UserAssigned', 'SystemAssigned, UserAssigned']:
                        site_data["user_assigned_identities"] = json.dumps(list(site.identity.user_assigned_identities.keys()) if site.identity.user_assigned_identities else [])
                
                self.collected_data["app_services"].append(site_data)
                logger.debug(f"Collected App Service: {site.name}")
        except Exception as e:
            logger.error(f"Error collecting App Services: {str(e)}")

    def _collect_user_assigned_identities(self, client: ManagedServiceIdentityClient, subscription_id: str):
        """Collect all User Assigned Managed Identities in the subscription."""
        logger.info(f"Collecting User Assigned Managed Identities for subscription {subscription_id}")
        
        try:
            for identity in client.user_assigned_identities.list_by_subscription():
                identity_data = {
                    "id": identity.id,
                    "name": identity.name,
                    "resource_group": self._extract_resource_group(identity.id),
                    "subscription_id": subscription_id,
                    "location": identity.location,
                    "client_id": identity.client_id,
                    "principal_id": identity.principal_id,
                    "tenant_id": identity.tenant_id,
                    "tags": json.dumps(identity.tags or {})
                }
                self.collected_data["user_assigned_identities"].append(identity_data)
                logger.debug(f"Collected User Assigned Identity: {identity.name}")
        except Exception as e:
            logger.error(f"Error collecting User Assigned Identities: {str(e)}")

    def _collect_system_assigned_identity(self, resource: Any, subscription_id: str):
        """Collect system-assigned managed identity information from a resource."""
        if hasattr(resource, 'identity') and resource.identity and resource.identity.principal_id:
            identity_data = {
                "id": f"{resource.id}/providers/Microsoft.ManagedIdentity/Identities/default",
                "resource_id": resource.id,
                "resource_name": resource.name,
                "resource_type": self._extract_resource_type(resource.id),
                "resource_group": self._extract_resource_group(resource.id),
                "subscription_id": subscription_id,
                "principal_id": resource.identity.principal_id,
                "tenant_id": resource.identity.tenant_id if hasattr(resource.identity, 'tenant_id') else self.tenant_id
            }
            self.collected_data["system_assigned_identities"].append(identity_data)
            logger.debug(f"Collected System Assigned Identity for {resource.name}")

    def _collect_aks_clusters(self, client: ContainerServiceClient, subscription_id: str):
        """Collect all AKS clusters in the subscription."""
        logger.info(f"Collecting AKS clusters for subscription {subscription_id}")
        
        try:
            for cluster in client.managed_clusters.list():
                cluster_data = {
                    "id": cluster.id,
                    "name": cluster.name,
                    "resource_group": self._extract_resource_group(cluster.id),
                    "subscription_id": subscription_id,
                    "location": cluster.location, 
                    "kubernetes_version": cluster.kubernetes_version,
                    "dns_prefix": cluster.dns_prefix,
                    "node_resource_group": cluster.node_resource_group,
                    "enable_rbac": cluster.enable_rbac,
                    "fqdn": cluster.fqdn,
                    "agent_pool_profiles": json.dumps([{
                        "name": profile.name,
                        "count": profile.count,
                        "vm_size": profile.vm_size,
                        "os_type": profile.os_type,
                        "max_pods": profile.max_pods,
                        "type": profile.type
                    } for profile in cluster.agent_pool_profiles]) if cluster.agent_pool_profiles else "[]",
                    "tags": json.dumps(cluster.tags or {})
                }
                
                # Check for system-assigned managed identity
                if hasattr(cluster, 'identity') and cluster.identity:
                    cluster_data["identity_type"] = cluster.identity.type
                    if cluster.identity.type in ['SystemAssigned', 'SystemAssigned, UserAssigned']:
                        self._collect_system_assigned_identity(cluster, subscription_id)
                    
                    if cluster.identity.type in ['UserAssigned', 'SystemAssigned, UserAssigned']:
                        cluster_data["user_assigned_identities"] = json.dumps(list(cluster.identity.user_assigned_identities.keys()) if cluster.identity.user_assigned_identities else [])
                
                self.collected_data["aks_clusters"].append(cluster_data)
                logger.debug(f"Collected AKS Cluster: {cluster.name}")
        except Exception as e:
            logger.error(f"Error collecting AKS clusters: {str(e)}")

    def _collect_automation_accounts(self, client: AutomationClient, subscription_id: str):
        """Collect all Automation Accounts in the subscription."""
        logger.info(f"Collecting Automation Accounts for subscription {subscription_id}")
        
        try:
            for automation_account in client.automation_account.list_by_subscription():
                account_data = {
                    "id": automation_account.id,
                    "name": automation_account.name,
                    "resource_group": self._extract_resource_group(automation_account.id),
                    "subscription_id": subscription_id,
                    "location": automation_account.location,
                    "sku": automation_account.sku.name if automation_account.sku else None,
                    "state": automation_account.state,
                    "creation_time": str(automation_account.creation_time) if automation_account.creation_time else None,
                    "last_modified_time": str(automation_account.last_modified_time) if automation_account.last_modified_time else None,
                    "tags": json.dumps(automation_account.tags or {})
                }
                
                # Check for system-assigned managed identity
                if hasattr(automation_account, 'identity') and automation_account.identity:
                    account_data["identity_type"] = automation_account.identity.type
                    if automation_account.identity.type in ['SystemAssigned', 'SystemAssigned, UserAssigned']:
                        self._collect_system_assigned_identity(automation_account, subscription_id)
                    
                    if automation_account.identity.type in ['UserAssigned', 'SystemAssigned, UserAssigned']:
                        account_data["user_assigned_identities"] = json.dumps(list(automation_account.identity.user_assigned_identities.keys()) if automation_account.identity.user_assigned_identities else [])
                
                self.collected_data["automation_accounts"].append(account_data)
                logger.debug(f"Collected Automation Account: {automation_account.name}")
        except Exception as e:
            logger.error(f"Error collecting Automation Accounts: {str(e)}")

    def _collect_cosmos_db_accounts(self, client: CosmosDBManagementClient, subscription_id: str):
        """Collect all Cosmos DB accounts in the subscription."""
        logger.info(f"Collecting Cosmos DB accounts for subscription {subscription_id}")
        
        try:
            for account in client.database_accounts.list():
                account_data = {
                    "id": account.id,
                    "name": account.name,
                    "resource_group": self._extract_resource_group(account.id),
                    "subscription_id": subscription_id,
                    "location": account.location,
                    "kind": account.kind,
                    "database_account_offer_type": account.database_account_offer_type,
                    "document_endpoint": account.document_endpoint,
                    "consistency_policy": json.dumps({
                        "default_consistency_level": account.consistency_policy.default_consistency_level,
                        "max_staleness_prefix": account.consistency_policy.max_staleness_prefix,
                        "max_interval_in_seconds": account.consistency_policy.max_interval_in_seconds
                    }) if account.consistency_policy else "{}",
                    "locations": json.dumps([{
                        "name": loc.location_name,
                        "failover_priority": loc.failover_priority
                    } for loc in account.locations]) if account.locations else "[]",
                    "tags": json.dumps(account.tags or {})
                }
                
                # Check for system-assigned managed identity
                if hasattr(account, 'identity') and account.identity:
                    account_data["identity_type"] = account.identity.type
                    if account.identity.type in ['SystemAssigned', 'SystemAssigned, UserAssigned']:
                        self._collect_system_assigned_identity(account, subscription_id)
                    
                    if account.identity.type in ['UserAssigned', 'SystemAssigned, UserAssigned']:
                        account_data["user_assigned_identities"] = json.dumps(list(account.identity.user_assigned_identities.keys()) if account.identity.user_assigned_identities else [])
                
                self.collected_data["cosmos_db_accounts"].append(account_data)
                logger.debug(f"Collected Cosmos DB Account: {account.name}")
        except Exception as e:
            logger.error(f"Error collecting Cosmos DB accounts: {str(e)}")

    def _collect_sql_servers(self, client: SqlManagementClient, subscription_id: str):
        """Collect all SQL servers in the subscription."""
        logger.info(f"Collecting SQL servers for subscription {subscription_id}")
        
        try:
            for server in client.servers.list():
                server_data = {
                    "id": server.id,
                    "name": server.name,
                    "resource_group": self._extract_resource_group(server.id),
                    "subscription_id": subscription_id,
                    "location": server.location,
                    "version": server.version,
                    "administrator_login": server.administrator_login,
                    "fully_qualified_domain_name": server.fully_qualified_domain_name,
                    "state": server.state,
                    "tags": json.dumps(server.tags or {})
                }
                
                # Check for system-assigned managed identity
                if hasattr(server, 'identity') and server.identity:
                    server_data["identity_type"] = server.identity.type
                    if server.identity.type in ['SystemAssigned', 'SystemAssigned, UserAssigned']:
                        self._collect_system_assigned_identity(server, subscription_id)
                    
                    if server.identity.type in ['UserAssigned', 'SystemAssigned, UserAssigned']:
                        server_data["user_assigned_identities"] = json.dumps(list(server.identity.user_assigned_identities.keys()) if server.identity.user_assigned_identities else [])
                
                self.collected_data["sql_servers"].append(server_data)
                logger.debug(f"Collected SQL Server: {server.name}")
                
                # Try to collect databases for this server
                try:
                    resource_group = self._extract_resource_group(server.id)
                    for db in client.databases.list_by_server(resource_group, server.name):
                        logger.debug(f"Found database {db.name} on server {server.name}")
                except Exception as e:
                    logger.error(f"Error collecting databases for SQL server {server.name}: {str(e)}")
        except Exception as e:
            logger.error(f"Error collecting SQL servers: {str(e)}")

    def _collect_logic_apps(self, client: LogicManagementClient, subscription_id: str):
        """Collect all Logic Apps in the subscription."""
        logger.info(f"Collecting Logic Apps for subscription {subscription_id}")
        
        try:
            for workflow in client.workflows.list_by_subscription():
                workflow_data = {
                    "id": workflow.id,
                    "name": workflow.name,
                    "resource_group": self._extract_resource_group(workflow.id),
                    "subscription_id": subscription_id,
                    "location": workflow.location,
                    "state": workflow.state,
                    "created_time": str(workflow.created_time) if workflow.created_time else None,
                    "changed_time": str(workflow.changed_time) if workflow.changed_time else None,
                    "access_endpoint": workflow.access_endpoint,
                    "tags": json.dumps(workflow.tags or {})
                }
                
                # Check for system-assigned managed identity
                if hasattr(workflow, 'identity') and workflow.identity:
                    workflow_data["identity_type"] = workflow.identity.type
                    if workflow.identity.type in ['SystemAssigned', 'SystemAssigned, UserAssigned']:
                        self._collect_system_assigned_identity(workflow, subscription_id)
                    
                    if workflow.identity.type in ['UserAssigned', 'SystemAssigned, UserAssigned']:
                        workflow_data["user_assigned_identities"] = json.dumps(list(workflow.identity.user_assigned_identities.keys()) if workflow.identity.user_assigned_identities else [])
                
                self.collected_data["logic_apps"].append(workflow_data)
                logger.debug(f"Collected Logic App: {workflow.name}")
        except Exception as e:
            logger.error(f"Error collecting Logic Apps: {str(e)}")

    def _collect_data_factories(self, client: DataFactoryManagementClient, subscription_id: str):
        """Collect all Data Factories in the subscription."""
        logger.info(f"Collecting Data Factories for subscription {subscription_id}")
        
        try:
            for factory in client.factories.list():
                factory_data = {
                    "id": factory.id,
                    "name": factory.name,
                    "resource_group": self._extract_resource_group(factory.id),
                    "subscription_id": subscription_id,
                    "location": factory.location,
                    "provisioning_state": factory.provisioning_state,
                    "create_time": str(factory.create_time) if factory.create_time else None,
                    "version": factory.version,
                    "repo_configuration": json.dumps(factory.repo_configuration.to_dict()) if factory.repo_configuration else None,
                    "tags": json.dumps(factory.tags or {})
                }
                
                # Check for system-assigned managed identity
                if hasattr(factory, 'identity') and factory.identity:
                    factory_data["identity_type"] = factory.identity.type
                    if factory.identity.type in ['SystemAssigned', 'SystemAssigned, UserAssigned']:
                        self._collect_system_assigned_identity(factory, subscription_id)
                    
                    if factory.identity.type in ['UserAssigned', 'SystemAssigned, UserAssigned']:
                        factory_data["user_assigned_identities"] = json.dumps(list(factory.identity.user_assigned_identities.keys()) if factory.identity.user_assigned_identities else [])
                
                self.collected_data["data_factories"].append(factory_data)
                logger.debug(f"Collected Data Factory: {factory.name}")
        except Exception as e:
            logger.error(f"Error collecting Data Factories: {str(e)}")

    def _collect_rbac_assignments(self, client: AuthorizationManagementClient, subscription_id: str):
        """Collect all RBAC role assignments in the subscription."""
        logger.info(f"Collecting RBAC role assignments for subscription {subscription_id}")
        
        try:
            for assignment in client.role_assignments.list_for_subscription():
                assignment_data = {
                    "id": assignment.id,
                    "name": assignment.name,
                    "role_definition_id": assignment.role_definition_id,
                    "principal_id": assignment.principal_id,
                    "principal_type": assignment.principal_type,
                    "scope": assignment.scope,
                    "subscription_id": subscription_id
                }
                self.collected_data["rbac_assignments"].append(assignment_data)
                logger.debug(f"Collected RBAC assignment: {assignment.name}")
        except Exception as e:
            logger.error(f"Error collecting RBAC role assignments: {str(e)}")

    def _collect_rbac_definitions(self, client: AuthorizationManagementClient, subscription_id: str):
        """Collect all RBAC role definitions in the subscription."""
        logger.info(f"Collecting RBAC role definitions for subscription {subscription_id}")
        
        try:
            for definition in client.role_definitions.list(scope=f"/subscriptions/{subscription_id}"):
                definition_data = {
                    "id": definition.id,
                    "name": definition.name,
                    "role_name": definition.role_name,
                    "description": definition.description,
                    "role_type": definition.role_type,
                    "permissions": json.dumps([{
                        "actions": perm.actions,
                        "not_actions": perm.not_actions,
                        "data_actions": perm.data_actions,
                        "not_data_actions": perm.not_data_actions
                    } for perm in definition.permissions]) if definition.permissions else "[]",
                    "assignable_scopes": json.dumps(definition.assignable_scopes),
                    "subscription_id": subscription_id
                }
                self.collected_data["rbac_definitions"].append(definition_data)
                logger.debug(f"Collected RBAC definition: {definition.role_name}")
        except Exception as e:
            logger.error(f"Error collecting RBAC role definitions: {str(e)}")

    def collect_entraid(self):
        """Collect EntraID (formerly Azure AD) resources."""
        logger.info(f"Collecting EntraID (AAD) resources for tenant {self.tenant_id}")
        
        try:
            # Get access token for Microsoft Graph API
            access_token = self._get_graph_token()
            if not access_token:
                logger.error("Could not obtain access token for Microsoft Graph")
                return
            
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            
            # Collect users
            logger.info("Collecting EntraID users")
            users_url = "https://graph.microsoft.com/v1.0/users"
            users = self._graph_api_get_all(users_url, headers)
            
            for user in users:
                user_data = {
                    "id": user.get("id"),
                    "tenant_id": self.tenant_id,
                    "userPrincipalName": user.get("userPrincipalName"),
                    "displayName": user.get("displayName"),
                    "mail": user.get("mail"),
                    "accountEnabled": user.get("accountEnabled"),
                    "onPremisesSyncEnabled": user.get("onPremisesSyncEnabled"),
                    "createdDateTime": user.get("createdDateTime"),
                    "userType": user.get("userType")
                }
                self.collected_data["entra_id_users"].append(user_data)
            
            logger.info(f"Collected {len(users)} EntraID users")
            
            # Collect groups concurrently
            logger.info("Collecting EntraID groups")
            groups_url = "https://graph.microsoft.com/v1.0/groups"
            groups = self._graph_api_get_all(groups_url, headers)
            group_data_list = []
            for group in groups:
                group_data = {
                    "id": group.get("id"),
                    "tenant_id": self.tenant_id,
                    "displayName": group.get("displayName"),
                    "description": group.get("description"),
                    "mail": group.get("mail"),
                    "mailEnabled": group.get("mailEnabled"),
                    "securityEnabled": group.get("securityEnabled"),
                    "groupTypes": json.dumps(group.get("groupTypes", [])),
                    "createdDateTime": group.get("createdDateTime")
                }
                group_data_list.append(group_data)
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_group = {
                    executor.submit(self._graph_api_get_all, f"https://graph.microsoft.com/v1.0/groups/{group_data['id']}/owners", headers): group_data
                    for group_data in group_data_list
                }
                for future in as_completed(future_to_group):
                    group_data = future_to_group[future]
                    try:
                        owners = future.result()
                    except Exception as e:
                        logger.warning(f"Failed to get owners for group {group_data['id']}: {str(e)}")
                        owners = []
                    if owners:
                        group_data["ownerIds"] = json.dumps([owner.get("id") for owner in owners])
                        group_data["ownerNames"] = json.dumps([owner.get("displayName") for owner in owners])
                    else:
                        group_data["ownerIds"] = json.dumps([])
                        group_data["ownerNames"] = json.dumps([])
            self.collected_data["entra_id_groups"].extend(group_data_list)
            logger.info(f"Collected {len(groups)} EntraID groups with owner information")
            
            # Collect service principals concurrently
            logger.info("Collecting service principals")
            sp_url = "https://graph.microsoft.com/v1.0/servicePrincipals"
            service_principals = self._graph_api_get_all(sp_url, headers)
            sp_data_list = []
            for sp in service_principals:
                sp_data = {
                    "id": sp.get("id"),
                    "tenant_id": self.tenant_id,
                    "appId": sp.get("appId"),
                    "displayName": sp.get("displayName"),
                    "appOwnerOrganizationId": sp.get("appOwnerOrganizationId"),
                    "appRoleAssignmentRequired": sp.get("appRoleAssignmentRequired"),
                    "servicePrincipalType": sp.get("servicePrincipalType"),
                    "createdDateTime": sp.get("createdDateTime")
                }
                sp_data_list.append(sp_data)
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_sp = {
                    executor.submit(self._graph_api_get_all, f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_data['id']}/owners", headers): sp_data
                    for sp_data in sp_data_list
                }
                for future in as_completed(future_to_sp):
                    sp_data = future_to_sp[future]
                    try:
                        owners = future.result()
                    except Exception as e:
                        logger.warning(f"Failed to get owners for service principal {sp_data['id']}: {str(e)}")
                        owners = []
                    if owners:
                        sp_data["ownerIds"] = json.dumps([owner.get("id") for owner in owners])
                        sp_data["ownerNames"] = json.dumps([owner.get("displayName") for owner in owners])
                    else:
                        sp_data["ownerIds"] = json.dumps([])
                        sp_data["ownerNames"] = json.dumps([])
            self.collected_data["entra_id_service_principals"].extend(sp_data_list)
            logger.info(f"Collected {len(service_principals)} service principals with owner information")
            
        except Exception as e:
            logger.error(f"Error collecting EntraID resources: {str(e)}")

    def _get_graph_token(self) -> str:
        """Get an access token for Microsoft Graph API."""
        try:
            # Try to use azure-identity DefaultAzureCredential
            from azure.identity import DefaultAzureCredential
            from azure.core.exceptions import ClientAuthenticationError
            
            try:
                credential = DefaultAzureCredential()
                token = credential.get_token("https://graph.microsoft.com/.default")
                return token.token
            except ClientAuthenticationError as e:
                logger.error(f"Could not get token using DefaultAzureCredential: {str(e)}")
                # Fall back to Azure CLI
                pass
            
            # Try getting token using Azure CLI
            import subprocess
            try:
                result = subprocess.run(
                    ["az", "account", "get-access-token", "--resource", "https://graph.microsoft.com"],
                    stdout=subprocess.PIPE,
                    check=True,
                    text=True
                )
                token_data = json.loads(result.stdout)
                return token_data["accessToken"]
            except (subprocess.SubprocessError, json.JSONDecodeError) as e:
                logger.error(f"Could not get token using Azure CLI: {str(e)}")
                return None
        except Exception as e:
            logger.error(f"Error getting Microsoft Graph token: {str(e)}")
            return None

    def _extract_resource_group(self, resource_id: str) -> str:
        """Extract resource group name from a resource ID."""
        if not resource_id:
            return None
        parts = resource_id.split('/')
        try:
            if len(parts) > 4 and parts[3].lower() == 'resourcegroups':
                return parts[4]
        except (IndexError, AttributeError):
            pass
        return None

    def _extract_resource_type(self, resource_id: str) -> str:
        """Extract resource type from a resource ID."""
        if not resource_id:
            return None
        parts = resource_id.split('/')
        try:
            if len(parts) > 7:
                return f"{parts[6]}/{parts[7]}"
        except (IndexError, AttributeError):
            pass
        return None

    def _save_results_csv(self):
        """Save all collected data to CSV files."""
        logger.info(f"Saving collected data to CSV files in {self.output_dir}")
        
        for resource_type, resources in self.collected_data.items():
            if not resources:
                logger.info(f"No {resource_type} found, skipping CSV creation")
                continue
                
            output_file = os.path.join(self.output_dir, f"{resource_type}.csv")
            try:
                # Add a "type" field to each record if not already present.
                for resource in resources:
                    if "type" not in resource:
                        resource["type"] = resource_type
                with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                    # Compute the union of all keys in all records
                    fieldnames = set()
                    for resource in resources:
                        fieldnames.update(resource.keys())
                    fieldnames = list(fieldnames)
                    
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(resources)
                    logger.info(f"Saved {len(resources)} {resource_type} to {output_file}")
            except Exception as e:
                logger.error(f"Error saving {resource_type} to CSV: {str(e)}")

    def export_to_json(self, filename: str = "azure_data.json"):
        """Export all collected data to a single JSON file."""
        output_file = os.path.join(self.output_dir, filename)
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.collected_data, f, indent=2)
            logger.info(f"Exported all collected data to {output_file}")
        except Exception as e:
            logger.error(f"Error exporting data to JSON: {str(e)}")


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Azure Resource Collector')
    parser.add_argument('--output-dir', default='azure_data', help='Directory to store collected data')
    parser.add_argument('--tenant-id', help='Azure tenant ID to collect from')
    parser.add_argument('--collect-entraid', action='store_true', help='Collect EntraID (formerly Azure AD) resources')
    parser.add_argument('--export-json', action='store_true', help='Export data to JSON in addition to CSV')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    return parser.parse_args()


def main():
    """Main entry point for the script."""
    args = parse_args()
    
    # Set debug logging if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Create and run collector
    try:
        collector = AzureCollector(output_dir=args.output_dir, tenant_id=args.tenant_id)
        collector.collect_all(collect_entraid=args.collect_entraid)
        
        # Export to JSON if requested
        if args.export_json:
            collector.export_to_json()
        
        logger.info("Azure Resource Collection complete")
    except Exception as e:
        logger.error(f"Error in Azure Resource Collection: {str(e)}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
