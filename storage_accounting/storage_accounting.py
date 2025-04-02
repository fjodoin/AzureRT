#!/usr/bin/env python3
"""
Azure Storage Account Scanner
-----------------------------
This script scans Azure subscriptions for storage accounts and their containers,
generating an interactive HTML report highlighting public vs private access.
"""

import os
import json
import time
import argparse
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qs

class AzureStorageScanner:
    def __init__(self, use_cli=True):
        self.use_cli = use_cli
        self.token = None
        self.subscriptions = []
        self.storage_accounts = []
        self.resource_groups = set()
        self.locations = set()
        self.api_version = "2021-09-01"
        self.headers = {}
        
    def authenticate(self):
        """Authenticate using Azure CLI or environment variables"""
        if self.use_cli:
            print("[*] Authenticating using Azure CLI...")
            try:
                import subprocess
                result = subprocess.run(
                    ["az", "account", "get-access-token", "--resource", "https://management.azure.com/"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True
                )
                token_data = json.loads(result.stdout)
                self.token = token_data["accessToken"]
                print("[+] Authentication successful!")
            except Exception as e:
                print(f"[!] Authentication failed: {str(e)}")
                print("[*] Please ensure Azure CLI is installed and you are logged in.")
                print("    Try running 'az login' first.")
                exit(1)
        else:
            print("[*] Attempting to authenticate using environment variables...")
            # Implement your environment variable based auth here if needed
            raise NotImplementedError("Environment variable authentication not implemented yet.")
        
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
    
    def get_subscriptions(self):
        """Get all accessible subscriptions"""
        print("[*] Retrieving subscriptions...")
        url = "https://management.azure.com/subscriptions?api-version=2020-01-01"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()
            
            if "value" in data:
                self.subscriptions = data["value"]
                print(f"[+] Found {len(self.subscriptions)} subscription(s)")
            else:
                print("[!] No subscriptions found or no access to subscriptions")
                
        except Exception as e:
            print(f"[!] Error retrieving subscriptions: {str(e)}")
    
    def get_storage_accounts(self):
        """Get all storage accounts across all subscriptions"""
        print("[*] Scanning for storage accounts...")
        
        for sub in self.subscriptions:
            sub_id = sub["subscriptionId"]
            sub_name = sub["displayName"]
            print(f"[*] Scanning subscription: {sub_name} ({sub_id})")
            
            url = f"https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.Storage/storageAccounts?api-version={self.api_version}"
            
            try:
                response = requests.get(url, headers=self.headers)
                response.raise_for_status()
                data = response.json()
                
                if "value" in data and len(data["value"]) > 0:
                    accounts = data["value"]
                    print(f"[+] Found {len(accounts)} storage account(s) in subscription {sub_name}")
                    
                    for account in accounts:
                        # Add subscription info to each account
                        account["subscriptionId"] = sub_id
                        account["subscriptionName"] = sub_name
                        
                        # Extract resource group
                        if "id" in account:
                            parts = account["id"].split("/")
                            if len(parts) > 4:
                                try:
                                    rg_index = parts.index("resourceGroups")
                                    if rg_index + 1 < len(parts):
                                        account["resourceGroup"] = parts[rg_index + 1]
                                        self.resource_groups.add(account["resourceGroup"])
                                except ValueError:
                                    pass
                        
                        # Extract location
                        if "location" in account:
                            self.locations.add(account["location"])
                        
                        self.storage_accounts.append(account)
                else:
                    print(f"[!] No storage accounts found in subscription {sub_name}")
                
            except Exception as e:
                print(f"[!] Error retrieving storage accounts for subscription {sub_id}: {str(e)}")
    
    def get_container_access_levels(self):
        """Get container access levels for each storage account"""
        print("[*] Retrieving container access levels...")
        
        for account in self.storage_accounts:
            account_name = account["name"]
            sub_id = account["subscriptionId"]
            
            # Initialize containers list
            account["containers"] = []
            
            # Extract resource group from the storage account ID
            resource_group = account.get("resourceGroup", "")
            
            if not resource_group:
                print(f"[!] Couldn't determine resource group for {account_name}, skipping containers")
                continue
            
            url = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.Storage/storageAccounts/{account_name}/blobServices/default/containers?api-version={self.api_version}"
            
            try:
                response = requests.get(url, headers=self.headers)
                if response.status_code == 403:
                    print(f"[!] Insufficient permissions to list containers for {account_name}")
                    continue
                
                response.raise_for_status()
                data = response.json()
                
                if "value" in data:
                    containers = data["value"]
                    print(f"[+] Found {len(containers)} container(s) in storage account {account_name}")
                    account["containers"] = containers
                else:
                    print(f"[!] No containers found in storage account {account_name}")
                
            except Exception as e:
                print(f"[!] Error retrieving containers for storage account {account_name}: {str(e)}")
    
    def is_storage_account_public(self, account):
        """Determine if a storage account is publicly accessible"""
        # Check if public network access is enabled
        network_access = account.get("properties", {}).get("publicNetworkAccess", "")
        if network_access == "Disabled":
            return False
        
        # Check if blob public access is allowed
        blob_public_access = account.get("properties", {}).get("allowBlobPublicAccess", False)
        
        # Check network ACLs
        network_acls = account.get("properties", {}).get("networkAcls", {})
        default_action = network_acls.get("defaultAction", "")
        
        # If default action is allow or there are IP rules with default action deny
        # and no private endpoint connections, the account could be public
        is_public = (
            (blob_public_access is True) or 
            (default_action == "Allow") or
            (default_action == "Deny" and (
                len(network_acls.get("ipRules", [])) > 0 or
                len(network_acls.get("virtualNetworkRules", [])) > 0
            ))
        )
        
        return is_public
    
    def get_container_access_type(self, container):
        """Get the access type of a container"""
        public_access = container.get("properties", {}).get("publicAccess", "None")
        return public_access
    
    def generate_html_report(self, output_file="storage_report.html"):
        """Generate an interactive HTML report"""
        print(f"[*] Generating HTML report: {output_file}")
        
        # Count statistics
        total_accounts = len(self.storage_accounts)
        public_accounts = sum(1 for acc in self.storage_accounts if self.is_storage_account_public(acc))
        private_accounts = total_accounts - public_accounts
        
        public_containers = 0
        for account in self.storage_accounts:
            for container in account.get("containers", []):
                access_type = self.get_container_access_type(container)
                if access_type != "None":
                    public_containers += 1
        
        # Generate subscription options for JS
        subscription_options = ""
        for sub in self.subscriptions:
            subscription_options += f'<option value="{sub["subscriptionId"]}">{sub["displayName"]}</option>'
            
        # Generate resource group options for JS
        resource_group_options = ""
        for rg in sorted(self.resource_groups):
            resource_group_options += f'<option value="{rg}">{rg}</option>'
            
        # Generate location options for JS
        location_options = ""
        for loc in sorted(self.locations):
            location_options += f'<option value="{loc}">{loc}</option>'
        
        # Prepare HTML content with styles and JavaScript.
        # Note: All JavaScript template literals that should remain literal have their curly braces doubled.
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure Storage Accounts Security Report</title>
    <style>
        :root {{
            --primary-color: #0078d4;
            --primary-light: #0078d41a;
            --danger-color: #d93025;
            --danger-light: #d930251a;
            --warning-color: #f2c037;
            --warning-light: #f2c0371a;
            --success-color: #0f9d58;
            --success-light: #0f9d581a;
            --neutral-color: #616161;
            --neutral-light: #6161611a;
        }}
        * {{
            box-sizing: border-box;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
        }}
        body {{
            margin: 0;
            padding: 20px;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 10px;
            border-bottom: 1px solid #ddd;
        }}
        h1, h2, h3 {{
            color: #0078d4;
            margin-top: 0;
        }}
        .dashboard {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 20px;
            flex: 1;
            min-width: 200px;
        }}
        .card h3 {{
            margin-top: 0;
            color: #333;
            font-size: 16px;
        }}
        .card p {{
            font-size: 24px;
            font-weight: bold;
            margin: 10px 0;
        }}
        .danger {{
            color: var(--danger-color);
        }}
        .warning {{
            color: var(--warning-color);
        }}
        .success {{
            color: var(--success-color);
        }}
        .neutral {{
            color: var(--neutral-color);
        }}
        .filters {{
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}
        .filters .filter {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        select, .search-input {{
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            min-width: 180px;
        }}
        .search-input {{
            min-width: 250px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 5px;
            overflow: hidden;
            margin-bottom: 30px;
        }}
        th, td {{
            text-align: left;
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #0078d4;
            color: white;
            cursor: pointer;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .account-row {{
            cursor: pointer;
        }}
        .account-row.open {{
            background-color: var(--primary-light);
        }}
        .container-details {{
            display: none;
            background-color: #f9f9f9;
        }}
        .container-details.show {{
            display: table-row;
        }}
        .container-details-table {{
            margin: 0;
            width: 100%;
            box-shadow: none;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .badge-public {{
            background-color: var(--danger-light);
            color: var(--danger-color);
        }}
        .badge-private {{
            background-color: var(--success-light);
            color: var(--success-color);
        }}
        .badge-container-blob {{
            background-color: var(--danger-light);
            color: var(--danger-color);
        }}
        .badge-container-container {{
            background-color: var(--warning-light);
            color: var(--warning-color);
        }}
        .badge-container-none {{
            background-color: var(--success-light);
            color: var(--success-color);
        }}
        .stats-info {{
            margin-bottom: 15px;
            font-style: italic;
            color: #666;
        }}
        .empty-state {{
            text-align: center;
            padding: 40px;
            color: #666;
        }}
        .pagination {{
            display: flex;
            justify-content: center;
            gap: 5px;
            margin-top: 20px;
        }}
        .pagination button {{
            border: 1px solid #ddd;
            background-color: white;
            padding: 5px 10px;
            cursor: pointer;
            border-radius: 4px;
        }}
        .pagination button.active {{
            background-color: #0078d4;
            color: white;
            border-color: #0078d4;
        }}
        .pagination button:hover:not(.active) {{
            background-color: #f5f5f5;
        }}
        .details-cell {{
            padding: 0;
        }}
        .details-container {{
            padding: 15px;
        }}
        .detail-group {{
            margin-bottom: 15px;
        }}
        .detail-group h4 {{
            margin: 0 0 5px 0;
            font-size: 14px;
            color: #666;
        }}
        .detail-item {{
            display: flex;
            margin-bottom: 5px;
        }}
        .detail-label {{
            min-width: 160px;
            font-weight: bold;
            color: #333;
        }}
        .icon {{
            vertical-align: middle;
            margin-right: 5px;
        }}
        .toggle-details {{
            background: none;
            border: none;
            color: #0078d4;
            cursor: pointer;
            padding: 0;
            font-size: 14px;
        }}
        .timestamp {{
            text-align: right;
            font-size: 14px;
            color: #666;
            margin-top: 0;
        }}
        @media (max-width: 768px) {{
            .dashboard {{
                flex-direction: column;
            }}
            .card {{
                min-width: 100%;
            }}
        }}
    </style>
</head>
<body>
    <header>
        <div>
            <h1>Azure Storage Accounts Security Report</h1>
            <p class="timestamp">Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </header>

    <div class="dashboard">
        <div class="card">
            <h3>Total Storage Accounts</h3>
            <p class="neutral">{total_accounts}</p>
        </div>
        <div class="card">
            <h3>Public Storage Accounts</h3>
            <p class="{'danger' if public_accounts > 0 else 'success'}">{public_accounts}</p>
        </div>
        <div class="card">
            <h3>Private Storage Accounts</h3>
            <p class="success">{private_accounts}</p>
        </div>
        <div class="card">
            <h3>Public Containers</h3>
            <p class="{'danger' if public_containers > 0 else 'success'}">{public_containers}</p>
        </div>
    </div>

    <div class="filters">
        <div class="filter">
            <label for="access-filter">Access Type:</label>
            <select id="access-filter">
                <option value="all">All</option>
                <option value="public">Public</option>
                <option value="private">Private</option>
            </select>
        </div>
        <div class="filter">
            <label for="subscription-filter">Subscription:</label>
            <select id="subscription-filter">
                <option value="all">All</option>
                {subscription_options}
            </select>
        </div>
        <div class="filter">
            <label for="resource-group-filter">Resource Group:</label>
            <select id="resource-group-filter">
                <option value="all">All</option>
                {resource_group_options}
            </select>
        </div>
        <div class="filter">
            <label for="location-filter">Location:</label>
            <select id="location-filter">
                <option value="all">All</option>
                {location_options}
            </select>
        </div>
        <div class="filter">
            <label for="search">Search:</label>
            <input type="text" id="search" class="search-input" placeholder="Search storage accounts...">
        </div>
    </div>

    <p class="stats-info">Click on a storage account row to view its containers.</p>

    <table id="storage-accounts-table">
        <thead>
            <tr>
                <th data-sort="name">Name</th>
                <th data-sort="access">Access</th>
                <th data-sort="resourceGroup">Resource Group</th>
                <th data-sort="subscription">Subscription</th>
                <th data-sort="location">Location</th>
                <th data-sort="containers">Containers</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody id="storage-accounts-body">
            <!-- Data will be populated by JavaScript -->
        </tbody>
    </table>

    <div id="pagination" class="pagination">
        <!-- Pagination will be populated by JavaScript -->
    </div>

    <script>
        // Storage accounts data
        const storageAccounts = {json.dumps(self.storage_accounts)};
        
        // Variables for table state
        let currentSort = {{ column: 'name', direction: 'asc' }};
        let currentFilter = {{ 
            access: 'all', 
            subscription: 'all',
            resourceGroup: 'all',
            location: 'all',
            search: ''
        }};
        let currentPage = 1;
        const rowsPerPage = 10;
        
        // DOM elements
        const tableBody = document.getElementById('storage-accounts-body');
        const accessFilter = document.getElementById('access-filter');
        const subscriptionFilter = document.getElementById('subscription-filter');
        const resourceGroupFilter = document.getElementById('resource-group-filter');
        const locationFilter = document.getElementById('location-filter');
        const searchInput = document.getElementById('search');
        const paginationElement = document.getElementById('pagination');
        
        // Initialize the table
        document.addEventListener('DOMContentLoaded', () => {{
            // Add event listeners for sorting
            document.querySelectorAll('th[data-sort]').forEach(th => {{
                th.addEventListener('click', () => {{
                    const column = th.dataset.sort;
                    if (currentSort.column === column) {{
                        currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
                    }} else {{
                        currentSort = {{ column, direction: 'asc' }};
                    }}
                    renderTable();
                }});
            }});
            
            // Add event listeners for filtering
            accessFilter.addEventListener('change', () => {{
                currentFilter.access = accessFilter.value;
                currentPage = 1;
                renderTable();
            }});
            
            subscriptionFilter.addEventListener('change', () => {{
                currentFilter.subscription = subscriptionFilter.value;
                currentPage = 1;
                renderTable();
            }});
            
            resourceGroupFilter.addEventListener('change', () => {{
                currentFilter.resourceGroup = resourceGroupFilter.value;
                currentPage = 1;
                renderTable();
            }});
            
            locationFilter.addEventListener('change', () => {{
                currentFilter.location = locationFilter.value;
                currentPage = 1;
                renderTable();
            }});
            
            searchInput.addEventListener('input', () => {{
                currentFilter.search = searchInput.value.toLowerCase();
                currentPage = 1;
                renderTable();
            }});
            
            // Initial render
            renderTable();
        }});
        
        // Functions to determine if storage account is public and container access level
        function isStorageAccountPublic(account) {{
            const properties = account.properties || {{}};
            const networkAccess = properties.publicNetworkAccess || '';
            
            if (networkAccess === 'Disabled') {{
                return false;
            }}
            
            const blobPublicAccess = properties.allowBlobPublicAccess || false;
            const networkAcls = properties.networkAcls || {{}};
            const defaultAction = networkAcls.defaultAction || '';
            const ipRules = networkAcls.ipRules || [];
            const vnetRules = networkAcls.virtualNetworkRules || [];
            
            return (
                blobPublicAccess === true ||
                defaultAction === 'Allow' ||
                (defaultAction === 'Deny' && (ipRules.length > 0 || vnetRules.length > 0))
            );
        }}
        
        function getContainerAccessType(container) {{
            const properties = container.properties || {{}};
            return properties.publicAccess || 'None';
        }}
        
        // Function to render the table with current sort and filter
        function renderTable() {{
            // Filter accounts
            let filteredAccounts = storageAccounts.filter(account => {{
                // Access filter
                if (currentFilter.access !== 'all') {{
                    const isPublic = isStorageAccountPublic(account);
                    if (currentFilter.access === 'public' && !isPublic) return false;
                    if (currentFilter.access === 'private' && isPublic) return false;
                }}
                
                // Subscription filter
                if (currentFilter.subscription !== 'all' && 
                    account.subscriptionId !== currentFilter.subscription) {{
                    return false;
                }}
                
                // Resource group filter
                if (currentFilter.resourceGroup !== 'all' && 
                    account.resourceGroup !== currentFilter.resourceGroup) {{
                    return false;
                }}
                
                // Location filter
                if (currentFilter.location !== 'all' && 
                    account.location !== currentFilter.location) {{
                    return false;
                }}
                
                // Search filter
                if (currentFilter.search) {{
                    const searchTerm = currentFilter.search.toLowerCase();
                    const name = (account.name || '').toLowerCase();
                    const resourceGroup = (account.resourceGroup || '').toLowerCase();
                    const subscription = (account.subscriptionName || '').toLowerCase();
                    
                    return (
                        name.includes(searchTerm) || 
                        resourceGroup.includes(searchTerm) || 
                        subscription.includes(searchTerm)
                    );
                }}
                
                return true;
            }});
            
            // Sort accounts
            filteredAccounts.sort((a, b) => {{
                let valA, valB;
                
                switch (currentSort.column) {{
                    case 'name':
                        valA = a.name || '';
                        valB = b.name || '';
                        break;
                    case 'access':
                        valA = isStorageAccountPublic(a) ? 'public' : 'private';
                        valB = isStorageAccountPublic(b) ? 'public' : 'private';
                        break;
                    case 'resourceGroup':
                        valA = a.resourceGroup || '';
                        valB = b.resourceGroup || '';
                        break;
                    case 'subscription':
                        valA = a.subscriptionName || '';
                        valB = b.subscriptionName || '';
                        break;
                    case 'location':
                        valA = a.location || '';
                        valB = b.location || '';
                        break;
                    case 'containers':
                        valA = (a.containers || []).length;
                        valB = (b.containers || []).length;
                        break;
                    default:
                        valA = '';
                        valB = '';
                }}
                
                if (valA < valB) return currentSort.direction === 'asc' ? -1 : 1;
                if (valA > valB) return currentSort.direction === 'asc' ? 1 : -1;
                return 0;
            }});
            
            // Paginate accounts
            const totalPages = Math.ceil(filteredAccounts.length / rowsPerPage);
            if (currentPage > totalPages && totalPages > 0) {{
                currentPage = totalPages;
            }}
            
            const startIndex = (currentPage - 1) * rowsPerPage;
            const paginatedAccounts = filteredAccounts.slice(startIndex, startIndex + rowsPerPage);
            
            // Render pagination
            renderPagination(totalPages);
            
            // Clear table
            tableBody.innerHTML = '';
            
            // Empty state
            if (paginatedAccounts.length === 0) {{
                const emptyRow = document.createElement('tr');
                emptyRow.innerHTML = `<td colspan="7" class="empty-state">No storage accounts found matching the current filters.</td>`;
                tableBody.appendChild(emptyRow);
                return;
            }}
            
            // Render rows
            paginatedAccounts.forEach(account => {{
                const isPublic = isStorageAccountPublic(account);
                const accessBadgeClass = isPublic ? 'badge-public' : 'badge-private';
                const accessBadgeText = isPublic ? 'Public' : 'Private';
                
                const containerCount = (account.containers || []).length;
                const publicContainerCount = (account.containers || []).filter(
                    container => getContainerAccessType(container) !== 'None'
                ).length;
                
                // Create account row
                const accountRow = document.createElement('tr');
                accountRow.className = 'account-row';
                accountRow.dataset.accountId = account.id;
                accountRow.innerHTML = `
                    <td>${{account.name || ''}}</td>
                    <td><span class="badge ${{accessBadgeClass}}">${{accessBadgeText}}</span></td>
                    <td>${{account.resourceGroup || ''}}</td>
                    <td>${{account.subscriptionName || ''}}</td>
                    <td>${{account.location || ''}}</td>
                    <td>${{containerCount}} ${{publicContainerCount > 0 ? `<span class="badge badge-container-blob">${{publicContainerCount}} public</span>` : ''}}</td>
                    <td>
                        <button class="toggle-details">Show Details</button>
                    </td>
                `;
                tableBody.appendChild(accountRow);
                
                // Create container details row
                const detailsRow = document.createElement('tr');
                detailsRow.className = 'container-details';
                detailsRow.dataset.accountId = account.id;
                
                let detailsContent = '';
                
                // Account details
                detailsContent += `
                <div class="details-container">
                    <div class="detail-group">
                        <h4>Storage Account Details</h4>
                        <div class="detail-item">
                            <span class="detail-label">Account Type:</span>
                            <span>${{account.kind || 'Unknown'}}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">SKU:</span>
                            <span>${{account.sku ? account.sku.name : 'Unknown'}}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Allow Blob Public Access:</span>
                            <span>${{account.properties?.allowBlobPublicAccess === true ? 'Yes' : 'No'}}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Public Network Access:</span>
                            <span>${{account.properties?.publicNetworkAccess || 'Unknown'}}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Network Default Action:</span>
                            <span>${{account.properties?.networkAcls?.defaultAction || 'Unknown'}}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">HTTPS Only:</span>
                            <span>${{account.properties?.supportsHttpsTrafficOnly === true ? 'Yes' : 'No'}}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Minimum TLS Version:</span>
                            <span>${{account.properties?.minimumTlsVersion || 'Unknown'}}</span>
                        </div>
                    </div>`;
                
                // Container details
                if (containerCount > 0) {{
                    detailsContent += `
                    <div class="detail-group">
                        <h4>Container Details</h4>
                        <table class="container-details-table">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Public Access</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${{account.containers.map(container => `
                                    <tr>
                                        <td>${{container.name}}</td>
                                        <td>${{getContainerAccessType(container)}}</td>
                                    </tr>
                                `).join('')}}
                            </tbody>
                        </table>
                    </div>`;
                }}
                
                detailsContent += `</div>`;
                detailsRow.innerHTML = `<td colspan="7">${{detailsContent}}</td>`;
                tableBody.appendChild(detailsRow);
                
                // Toggle details event listener
                accountRow.querySelector('.toggle-details').addEventListener('click', () => {{
                    if (detailsRow.classList.contains('show')) {{
                        detailsRow.classList.remove('show');
                        accountRow.classList.remove('open');
                        accountRow.querySelector('.toggle-details').innerText = 'Show Details';
                    }} else {{
                        detailsRow.classList.add('show');
                        accountRow.classList.add('open');
                        accountRow.querySelector('.toggle-details').innerText = 'Hide Details';
                    }}
                }});
            }});
        }}
        
        // Function to render pagination buttons
        function renderPagination(totalPages) {{
            paginationElement.innerHTML = '';
            for (let i = 1; i <= totalPages; i++) {{
                const btn = document.createElement('button');
                btn.innerText = i;
                if (i === currentPage) {{
                    btn.classList.add('active');
                }}
                btn.addEventListener('click', () => {{
                    currentPage = i;
                    renderTable();
                }});
                paginationElement.appendChild(btn);
            }}
        }}
    </script>
</body>
</html>"""
        
        with open(output_file, "w") as f:
            f.write(html)
        print(f"[+] Report saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Azure Storage Account Scanner")
    parser.add_argument("--no-cli", action="store_true", help="Don't use Azure CLI for authentication")
    parser.add_argument("--output", default="storage_report.html", help="Output HTML report file")
    args = parser.parse_args()

    scanner = AzureStorageScanner(use_cli=not args.no_cli)
    scanner.authenticate()
    scanner.get_subscriptions()
    scanner.get_storage_accounts()
    scanner.get_container_access_levels()
    scanner.generate_html_report(output_file=args.output)

if __name__ == "__main__":
    main()

