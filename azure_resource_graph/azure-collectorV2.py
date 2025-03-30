#!/usr/bin/env python3
"""
Azure Resource Collector

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
            "network_interfaces": [],
            "virtual_networks": [],
            "subnets": [],
            "network_security_groups": [],
            "public_ips": [],
            "storage_accounts": [],
            "key_vaults": [],
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
            self.credentials, self.subscription_id = get_azure_cli_credentials(with_tenant=True)
            self.tenant_id = self.tenant_id or self.credentials[2]  # Fixed: Access tenant_id from tuple
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
        auth_client = AuthorizationManagementClient(self.credentials, subscription_id)
        
        # Collect resource groups
        self._collect_resource_groups(resource_client, subscription_id)
        
        # Collect compute resources
        self._collect_virtual_machines(compute_client, subscription_id)
        
        # Collect network resources
        self._collect_network_resources(network_client, subscription_id)
        
        # Collect storage accounts
        self._collect_storage_accounts(storage_client, subscription_id)
        
        # Collect key vaults
        self._collect_key_vaults(keyvault_client, subscription_id)
        
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
                self.collected_data["virtual_machines"].append(vm_data)
                logger.debug(f"Collected VM: {vm.name}")
        except Exception as e:
            logger.error(f"Error collecting virtual machines: {str(e)}")

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
                self.collected_data["storage_accounts"].append(sa_data)
                logger.debug(f"Collected Storage Account: {sa.name}")
        except Exception as e:
            logger.error(f"Error collecting storage accounts: {str(e)}")

    def _collect_key_vaults(self, client: KeyVaultManagementClient, subscription_id: str):
        """Collect all key vaults in the subscription."""
        logger.info(f"Collecting key vaults for subscription {subscription_id}")
        
        try:
            vaults_list = list(client.vaults.list())
            logger.info(f"Found {len(vaults_list)} key vaults in subscription {subscription_id}")
            
            for kv in vaults_list:
                try:
                    kv_data = {
                        "id": kv.id,
                        "name": kv.name,
                        "resource_group": self._extract_resource_group(kv.id),
                        "subscription_id": subscription_id,
                        "location": kv.location,
                        "tenant_id": kv.properties.tenant_id,
                        "sku": kv.properties.sku.name,
                        "enabled_for_deployment": kv.properties.enabled_for_deployment,
                        "enabled_for_disk_encryption": kv.properties.enabled_for_disk_encryption,
                        "enabled_for_template_deployment": kv.properties.enabled_for_template_deployment
                    }
                    
                    try:
                        if kv.properties.access_policies:
                            policies = []
                            for policy in kv.properties.access_policies:
                                policy_data = {
                                    "tenant_id": policy.tenant_id,
                                    "object_id": policy.object_id,
                                    "permissions": {
                                        "keys": policy.permissions.keys or [] if hasattr(policy.permissions, 'keys') else [],
                                        "secrets": policy.permissions.secrets or [] if hasattr(policy.permissions, 'secrets') else [],
                                        "certificates": policy.permissions.certificates or [] if hasattr(policy.permissions, 'certificates') else []
                                    }
                                }
                                policies.append(policy_data)
                            kv_data["access_policies"] = json.dumps(policies)
                        else:
                            kv_data["access_policies"] = "[]"
                    except Exception as access_policy_error:
                        logger.error(f"Error processing access policies for key vault {kv.name}: {str(access_policy_error)}")
                        kv_data["access_policies"] = "[]"
                    
                    kv_data["tags"] = json.dumps(kv.tags or {})
                    self.collected_data["key_vaults"].append(kv_data)
                    logger.debug(f"Collected Key Vault: {kv.name}")
                except Exception as kv_error:
                    logger.error(f"Error processing key vault {kv.name}: {str(kv_error)}")
        except Exception as e:
            logger.error(f"Error collecting key vaults for subscription {subscription_id}: {str(e)}")

    def _collect_rbac_assignments(self, client: AuthorizationManagementClient, subscription_id: str):
        """Collect all RBAC role assignments in the subscription."""
        logger.info(f"Collecting RBAC role assignments for subscription {subscription_id}")
        
        try:
            for assignment in client.role_assignments.list_for_subscription():
                assignment_data = {
                    "id": assignment.id,
                    "name": assignment.name,
                    "scope": assignment.scope,
                    "subscription_id": subscription_id,
                    "principal_id": assignment.principal_id,
                    "principal_type": assignment.principal_type,
                    "role_definition_id": assignment.role_definition_id
                }
                self.collected_data["rbac_assignments"].append(assignment_data)
                logger.debug(f"Collected RBAC Assignment: {assignment.name}")
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
                    "subscription_id": subscription_id,
                    "role_name": definition.role_name,
                    "description": definition.description,
                    "role_type": definition.role_type,
                    "permissions": json.dumps([{
                        "actions": perm.actions if perm.actions else [],
                        "not_actions": perm.not_actions if perm.not_actions else [],
                        "data_actions": perm.data_actions if perm.data_actions else [],
                        "not_data_actions": perm.not_data_actions if perm.not_data_actions else []
                    } for perm in definition.permissions]) if definition.permissions else "[]"
                }
                self.collected_data["rbac_definitions"].append(definition_data)
                logger.debug(f"Collected RBAC Definition: {definition.role_name}")
        except Exception as e:
            logger.error(f"Error collecting RBAC role definitions: {str(e)}")

    def collect_entraid(self):
        """Collect EntraID resources using Microsoft Graph API."""
        logger.info("Collecting EntraID resources")
        try:
            if isinstance(self.credentials, DefaultAzureCredential):
                graph_credential = DefaultAzureCredential()
                try:
                    token = graph_credential.get_token("https://graph.microsoft.com/.default").token
                    logger.info("Successfully acquired token for Microsoft Graph API")
                except Exception as e:
                    logger.error(f"Error getting token for Microsoft Graph API: {str(e)}")
                    token = graph_credential.get_token("https://management.azure.com/.default").token
                    logger.info("Using management token for Microsoft Graph API (may have limited access)")
            else:
                logger.warning("Using Azure CLI credential mode for Microsoft Graph API")
                import subprocess
                result = subprocess.run(
                    ["az", "account", "get-access-token", "--resource", "https://graph.microsoft.com"],
                    capture_output=True, text=True
                )
                if result.returncode != 0:
                    raise Exception(f"Failed to get Microsoft Graph token using az CLI: {result.stderr}")
                token_data = json.loads(result.stdout)
                token = token_data.get("accessToken")
                if not token:
                    raise Exception("No token found in az CLI output")
            
            headers = {"Authorization": f"Bearer {token}"}
            
            # Collect EntraID users
            logger.info("Collecting EntraID users")
            users_url = "https://graph.microsoft.com/v1.0/users"
            try:
                users = self._graph_api_get_all(users_url, headers)
                logger.info(f"Found {len(users)} EntraID users")
                for user in users:
                    user_data = {
                        "id": user.get("id"),
                        "user_principal_name": user.get("userPrincipalName"),
                        "display_name": user.get("displayName"),
                        "mail": user.get("mail"),
                        "account_enabled": user.get("accountEnabled"),
                        "user_type": user.get("userType")
                    }
                    self.collected_data["entra_id_users"].append(user_data)
                    logger.debug(f"Collected EntraID User: {user.get('displayName')}")
            except Exception as e:
                logger.error(f"Error collecting EntraID users: {str(e)}")
            
            # Collect EntraID groups
            logger.info("Collecting EntraID groups")
            groups_url = "https://graph.microsoft.com/v1.0/groups"
            try:
                groups = self._graph_api_get_all(groups_url, headers)
                logger.info(f"Found {len(groups)} EntraID groups")
                for group in groups:
                    group_data = {
                        "id": group.get("id"),
                        "display_name": group.get("displayName"),
                        "mail": group.get("mail"),
                        "security_enabled": group.get("securityEnabled"),
                        "mail_enabled": group.get("mailEnabled")
                    }
                    self.collected_data["entra_id_groups"].append(group_data)
                    logger.debug(f"Collected EntraID Group: {group.get('displayName')}")
            except Exception as e:
                logger.error(f"Error collecting EntraID groups: {str(e)}")
            
            # Collect EntraID service principals
            logger.info("Collecting EntraID service principals")
            sp_url = "https://graph.microsoft.com/v1.0/servicePrincipals"
            try:
                service_principals = self._graph_api_get_all(sp_url, headers)
                logger.info(f"Found {len(service_principals)} EntraID service principals")
                for sp in service_principals:
                    sp_data = {
                        "id": sp.get("id"),
                        "display_name": sp.get("displayName"),
                        "app_id": sp.get("appId"),
                        "service_principal_type": sp.get("servicePrincipalType"),
                        "app_display_name": sp.get("displayName")
                    }
                    self.collected_data["entra_id_service_principals"].append(sp_data)
                    logger.debug(f"Collected EntraID Service Principal: {sp.get('displayName')}")
            except Exception as e:
                logger.error(f"Error collecting EntraID service principals: {str(e)}")
        except Exception as e:
            logger.error(f"Error in EntraID collection process: {str(e)}")

    def _extract_resource_group(self, resource_id: str) -> Optional[str]:
        """Extract resource group name from Azure resource ID."""
        if not resource_id:
            return None
        parts = resource_id.split('/')
        for i, part in enumerate(parts):
            if part.lower() == 'resourcegroups' and i + 1 < len(parts):
                return parts[i + 1]
        return None

    def _save_results_csv(self):
        """Save collected data to CSV files."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save each resource type to its own CSV file
        for resource_type, data in self.collected_data.items():
            if data:  # Only save if there is data
                output_file = os.path.join(self.output_dir, f"{resource_type}_{timestamp}.csv")
                # Use union of keys across all dictionaries in case they vary
                fieldnames = sorted({key for row in data for key in row.keys()})
                try:
                    with open(output_file, 'w', newline='') as csvfile:
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(data)
                    logger.info(f"Saved {len(data)} {resource_type} records to {output_file}")
                except Exception as e:
                    logger.error(f"Error writing CSV file for {resource_type}: {str(e)}")
        
        # Create a summary CSV file
        summary = {
            "collection_time": timestamp,
            "tenant_id": self.tenant_id,
            **{k: len(v) for k, v in self.collected_data.items()}
        }
        summary_file = os.path.join(self.output_dir, f"summary_{timestamp}.csv")
        try:
            with open(summary_file, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=summary.keys())
                writer.writeheader()
                writer.writerow(summary)
            logger.info(f"Summary saved to {summary_file}")
        except Exception as e:
            logger.error(f"Error writing summary CSV: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Azure Resource Collector")
    parser.add_argument("--output-dir", type=str, default="azure_data", help="Directory to store collected data")
    parser.add_argument("--tenant-id", type=str, default=None, help="Azure tenant ID")
    parser.add_argument("--collect-entraid", action="store_true", help="Collect EntraID resources using Microsoft Graph API")
    args = parser.parse_args()
    
    collector = AzureCollector(output_dir=args.output_dir, tenant_id=args.tenant_id)
    collector.collect_all(collect_entraid=args.collect_entraid)

if __name__ == "__main__":
    main()
