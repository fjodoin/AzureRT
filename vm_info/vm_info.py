import os
import json
from datetime import datetime
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient

# python3 -m pip install azure-identity azure-mgmt-compute azure-mgmt-network azure-mgmt-resource

def collect_virtual_machines():
    """
    Authenticates using DefaultAzureCredential and collects all virtual machines
    across subscriptions. For each VM, it retrieves full details (via get with expand)
    so that custom (user) data is available. It then collects:
      - Basic info (name, location, VM size, OS type, custom/user data)
      - Network interface details: private IPs, public IPs (if available), and NSG details.
    """
    credential = DefaultAzureCredential()
    subscription_client = SubscriptionClient(credential)
    vms = []

    for sub in subscription_client.subscriptions.list():
        sub_id = sub.subscription_id
        print(f"Collecting VMs from subscription: {sub_id}")
        compute_client = ComputeManagementClient(credential, sub_id)
        resource_client = ResourceManagementClient(credential, sub_id)
        network_client = NetworkManagementClient(credential, sub_id)

        for rg in resource_client.resource_groups.list():
            rg_name = rg.name
            print(f"  Checking resource group: {rg_name}")
            try:
                vm_list = compute_client.virtual_machines.list(rg_name)
            except Exception as e:
                print(f"Failed to list VMs in resource group {rg_name} in subscription {sub_id}: {e}")
                continue

            for vm in vm_list:
                try:
                    # Retrieve full details for the VM to capture custom_data
                    vm_full = compute_client.virtual_machines.get(rg_name, vm.name, expand="instanceView")
                    vm_info = {}
                    vm_info['subscription_id'] = sub_id
                    vm_info['resource_group'] = rg_name
                    vm_info['name'] = vm_full.name
                    vm_info['location'] = vm_full.location
                    vm_info['vm_size'] = vm_full.hardware_profile.vm_size if vm_full.hardware_profile else "N/A"
                    # OS type: try to use .value if available; otherwise use directly.
                    os_type = "N/A"
                    if vm_full.storage_profile and vm_full.storage_profile.os_disk and vm_full.storage_profile.os_disk.os_type:
                        try:
                            os_type = vm_full.storage_profile.os_disk.os_type.value
                        except AttributeError:
                            os_type = vm_full.storage_profile.os_disk.os_type
                    vm_info['os_type'] = os_type
                    # Retrieve custom (user) data
                    vm_info['custom_data'] = vm_full.os_profile.custom_data if vm_full.os_profile and vm_full.os_profile.custom_data else "N/A"

                    # Collect network interface information.
                    nic_infos = []
                    if vm_full.network_profile and vm_full.network_profile.network_interfaces:
                        for nic_ref in vm_full.network_profile.network_interfaces:
                            nic_id = nic_ref.id
                            parts = nic_id.split('/')
                            try:
                                rg_index = parts.index("resourceGroups")
                                nic_rg = parts[rg_index + 1]
                                nic_name = parts[-1]
                            except Exception as ex:
                                nic_rg = rg_name
                                nic_name = nic_ref.id
                            try:
                                nic = network_client.network_interfaces.get(nic_rg, nic_name)
                                private_ips = []
                                public_ips = []
                                for ipconfig in nic.ip_configurations:
                                    if ipconfig.private_ip_address:
                                        private_ips.append(ipconfig.private_ip_address)
                                    if ipconfig.public_ip_address and ipconfig.public_ip_address.id:
                                        pub_parts = ipconfig.public_ip_address.id.split('/')
                                        try:
                                            pub_rg_index = pub_parts.index("resourceGroups")
                                            pub_rg = pub_parts[pub_rg_index + 1]
                                            pub_name = pub_parts[-1]
                                            pub_ip = network_client.public_ip_addresses.get(pub_rg, pub_name)
                                            if pub_ip.ip_address:
                                                public_ips.append(pub_ip.ip_address)
                                        except Exception as ex:
                                            pass
                                nsg = nic.network_security_group
                                nsg_info = nsg.id if nsg else "None"
                                nic_infos.append({
                                    "nic_name": nic.name,
                                    "private_ips": private_ips,
                                    "public_ips": public_ips,
                                    "nsg": nsg_info
                                })
                            except Exception as e:
                                print(f"Error retrieving NIC {nic_name} in resource group {nic_rg}: {e}")
                    vm_info['network_interfaces'] = nic_infos
                    # (Optional) store full metadata if desired.
                    vm_info['metadata'] = vm_full.as_dict()
                    vms.append(vm_info)
                except Exception as e:
                    print(f"Failed to process VM {getattr(vm, 'name', 'Unknown')} in resource group {rg_name} in subscription {sub_id}: {e}")
                    continue
    return vms

def generate_html(vms):
    """
    Generates an HTML report that references external CSS (report.css) and JavaScript (report.js).
    The header and styling match your storage/account report style. The VM data is injected as a JSON blob
    into a global variable 'virtualMachines' for rendering.
    """
    vms_json = json.dumps(vms)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Azure Virtual Machines Security Report</title>
  <link rel="stylesheet" href="report.css">
</head>
<body>
  <header>
    <div>
      <h1>Azure Virtual Machines Security Report</h1>
      <p class="timestamp">Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
  </header>
  <div id="report-container">
    <!-- Dynamic content will be rendered by report.js -->
  </div>
  <script>
    const virtualMachines = {vms_json};
  </script>
  <script src="report.js"></script>
</body>
</html>
"""
    return html

def main():
    print("Collecting Azure Virtual Machines...")
    vms = collect_virtual_machines()
    if not vms:
        print("No Virtual Machines found.")
        return

    print(f"Collected {len(vms)} Virtual Machines. Generating HTML report...")
    html_content = generate_html(vms)
    output_file = "azure_vms_report.html"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"HTML report generated: {output_file}")

if __name__ == '__main__':
    main()
