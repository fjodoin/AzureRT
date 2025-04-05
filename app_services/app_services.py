import os
import json
from datetime import datetime
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.web import WebSiteManagementClient

# python3 -m pip install azure-identity azure-mgmt-resource azure-mgmt-web

def collect_app_services():
    """
    Authenticates with DefaultAzureCredential and iterates through all subscriptions.
    For each subscription, it collects App Services by enumerating resource groups and
    listing the web apps within each resource group. It retrieves details such as the Managed Identity type
    and aggregates the IDs from system-assigned and user-assigned identities.
    """
    credential = DefaultAzureCredential()
    subscription_client = SubscriptionClient(credential)
    app_services = []

    for sub in subscription_client.subscriptions.list():
        subscription_id = sub.subscription_id
        print(f"Collecting App Services from subscription: {subscription_id}")
        
        # Create clients for the current subscription
        web_client = WebSiteManagementClient(credential, subscription_id)
        resource_client = ResourceManagementClient(credential, subscription_id)
        
        try:
            for rg in resource_client.resource_groups.list():
                print(f"  Checking resource group: {rg.name}")
                try:
                    for app in web_client.web_apps.list_by_resource_group(rg.name):
                        # Determine Managed Identity details.
                        if hasattr(app, "identity") and app.identity:
                            managed_identity_type = app.identity.type  # e.g., "SystemAssigned", "UserAssigned", or both
                            system_assigned_id = getattr(app.identity, "principal_id", None)
                            user_assigned_identities = getattr(app.identity, "user_assigned_identities", None)
                            
                            id_list = []
                            if system_assigned_id:
                                id_list.append(f"System: {system_assigned_id}")
                            if user_assigned_identities:
                                for key, val in user_assigned_identities.items():
                                    # Try to retrieve the principal_id from the user-assigned identity object.
                                    user_principal_id = getattr(val, "principal_id", None)
                                    if user_principal_id:
                                        id_list.append(f"User: {user_principal_id}")
                                    else:
                                        id_list.append(f"User: {key}")
                            managed_identity_ids = ", ".join(id_list) if id_list else "None"
                        else:
                            managed_identity_type = "None"
                            managed_identity_ids = "None"

                        # Determine App Service type based on the 'kind' property.
                        app_type_raw = getattr(app, "kind", "")
                        if app_type_raw:
                            if "functionapp" in app_type_raw.lower():
                                app_type = "Function App"
                            elif "app" in app_type_raw.lower():
                                app_type = "Web App"
                            else:
                                app_type = app_type_raw
                        else:
                            app_type = "Web App"

                        app_info = {
                            "subscription_id": subscription_id,
                            "resource_group": rg.name,
                            "name": app.name,
                            "location": app.location,
                            "default_host_name": app.default_host_name,
                            "state": getattr(app, "state", "N/A"),
                            "managed_identity_type": managed_identity_type,
                            "managed_identity_ids": managed_identity_ids,
                            "app_type": app_type
                        }
                        app_services.append(app_info)
                except Exception as e:
                    print(f"    Failed to collect apps from resource group {rg.name} in subscription {subscription_id}: {str(e)}")
        except Exception as e:
            print(f"  Failed to list resource groups for subscription {subscription_id}: {str(e)}")
            
    return app_services

def generate_html(app_services):
    """
    Generates an HTML report that matches the look and feel of your storage account report.
    This output references external CSS (report.css) and JavaScript (report.js). The HTML includes a header
    with a timestamp, and the App Services data is injected as a JSON blob into a global variable 'appServices'
    for the external JavaScript to render.
    """
    app_services_json = json.dumps(app_services)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Azure App Services Security Report</title>
  <link rel="stylesheet" href="report.css">
</head>
<body>
  <header>
    <div>
      <h1>Azure App Services Security Report</h1>
      <p class="timestamp">Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
  </header>
  <div id="report-container">
    <!-- Dynamic content will be rendered by report.js -->
  </div>
  <script>
    const appServices = {app_services_json};
  </script>
  <script src="report.js"></script>
</body>
</html>
"""
    return html

def main():
    print("Collecting Azure App Services...")
    app_services = collect_app_services()
    if not app_services:
        print("No App Services found.")
        return

    print(f"Collected {len(app_services)} App Services. Generating HTML report...")
    html_content = generate_html(app_services)
    output_file = "azure_app_services_report.html"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"HTML report generated: {output_file}")

if __name__ == '__main__':
    main()
