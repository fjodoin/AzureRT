#!/usr/bin/env python3
"""
Azure Storage Account Scanner and HTML Report Generator
---------------------------------------------------------
This script collects Azure storage account and container information and then
generates an HTML report. The HTML output references external CSS and JavaScript
files (report.css and report.js) to handle styling and interactivity.
"""

import json
import argparse
import subprocess
import requests
import concurrent.futures
from datetime import datetime

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
        self.session = requests.Session()  # Use persistent session for all HTTP calls

    def authenticate(self):
        """Authenticate using Azure CLI."""
        if self.use_cli:
            print("[*] Authenticating using Azure CLI...")
            try:
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
                print("[*] Please ensure Azure CLI is installed and you are logged in (az login).")
                exit(1)
        else:
            raise NotImplementedError("Environment variable authentication not implemented yet.")
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

    def get_subscriptions(self):
        """Retrieve all accessible subscriptions."""
        print("[*] Retrieving subscriptions...")
        url = "https://management.azure.com/subscriptions?api-version=2020-01-01"
        try:
            response = self.session.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            if "value" in data:
                self.subscriptions = data["value"]
                print(f"[+] Found {len(self.subscriptions)} subscription(s)")
            else:
                print("[!] No subscriptions found or no access available.")
        except Exception as e:
            print(f"[!] Error retrieving subscriptions: {str(e)}")

    def get_storage_accounts(self):
        """Collect storage accounts from each subscription."""
        print("[*] Scanning for storage accounts...")

        def fetch_storage_accounts(sub):
            sub_id = sub["subscriptionId"]
            sub_name = sub["displayName"]
            print(f"[*] Scanning subscription: {sub_name} ({sub_id})")
            url = f"https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.Storage/storageAccounts?api-version={self.api_version}"
            local_accounts = []
            try:
                response = self.session.get(url, headers=self.headers, timeout=10)
                response.raise_for_status()
                data = response.json()
                if "value" in data and data["value"]:
                    accounts = data["value"]
                    print(f"[+] Found {len(accounts)} storage account(s) in subscription {sub_name}")
                    for account in accounts:
                        account["subscriptionId"] = sub_id
                        account["subscriptionName"] = sub_name
                        if "id" in account:
                            parts = account["id"].split("/")
                            if "resourceGroups" in parts:
                                rg_index = parts.index("resourceGroups")
                                if rg_index + 1 < len(parts):
                                    account["resourceGroup"] = parts[rg_index + 1]
                                    self.resource_groups.add(account["resourceGroup"])
                        if "location" in account:
                            self.locations.add(account["location"])
                        local_accounts.append(account)
                else:
                    print(f"[!] No storage accounts found in subscription {sub_name}")
            except Exception as e:
                print(f"[!] Error retrieving storage accounts for subscription {sub_id}: {str(e)}")
            return local_accounts

        self.storage_accounts = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(fetch_storage_accounts, sub): sub for sub in self.subscriptions}
            for future in concurrent.futures.as_completed(futures):
                self.storage_accounts.extend(future.result())

    def get_container_access_levels(self):
        """For each storage account, collect its container details."""
        print("[*] Retrieving container access levels...")

        def fetch_containers(account):
            account_name = account["name"]
            sub_id = account["subscriptionId"]
            resource_group = account.get("resourceGroup", "")
            if not resource_group:
                print(f"[!] Could not determine resource group for {account_name}, skipping containers.")
                return
            url = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.Storage/storageAccounts/{account_name}/blobServices/default/containers?api-version={self.api_version}"
            try:
                response = self.session.get(url, headers=self.headers, timeout=10)
                if response.status_code == 403:
                    print(f"[!] Insufficient permissions to list containers for {account_name}")
                    return
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

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(fetch_containers, account) for account in self.storage_accounts]
            concurrent.futures.wait(futures)

    def collect_data(self):
        """Run all collection steps and return the storage account data."""
        self.authenticate()
        self.get_subscriptions()
        self.get_storage_accounts()
        self.get_container_access_levels()
        return self.storage_accounts

def generate_html(data, output_file="storage_report.html"):
    """
    Generate an HTML report that references external CSS (report.css)
    and JavaScript (report.js). The data is injected as a JSON blob.
    """
    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Azure Storage Accounts Security Report</title>
  <link rel="stylesheet" href="report.css">
</head>
<body>
  <header>
    <div>
      <h1>Azure Storage Accounts Security Report</h1>
      <p class="timestamp">Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
  </header>
  <div id="report-container">
    <!-- Dynamic content will be rendered by report.js -->
  </div>
  <script>
    const storageAccounts = {json.dumps(data)};
  </script>
  <script src="report.js"></script>
</body>
</html>
"""
    with open(output_file, "w") as f:
        f.write(html_template)
    print(f"[+] HTML report generated and saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Azure Storage Account Scanner and HTML Reporter")
    parser.add_argument("--no-cli", action="store_true", help="Do not use Azure CLI for authentication")
    parser.add_argument("--output", default="storage_report.html", help="Output HTML report file")
    args = parser.parse_args()

    scanner = AzureStorageScanner(use_cli=not args.no_cli)
    storage_accounts = scanner.collect_data()
    generate_html(storage_accounts, output_file=args.output)

if __name__ == "__main__":
    main()
