import json
import subprocess
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

# The color palette (unchanged)
RESOURCE_COLORS = {
    "Microsoft.Compute/virtualMachines": "#1f77b4",
    "Microsoft.Compute/virtualMachineScaleSets": "#4E79A7",
    "Microsoft.Storage/storageAccounts": "#2CA02C",
    "Microsoft.KeyVault/vaults": "#9467BD",
    "Microsoft.Web/sites": "#E377C2",
    "Microsoft.ManagedIdentity/userAssignedIdentities": "#FF7F0E",
    "Microsoft.ContainerService/managedClusters": "#17BECF",
    "Microsoft.Automation/automationAccounts": "#8C564B",
    "Microsoft.DocumentDB/databaseAccounts": "#D62728",
    "Microsoft.Sql/servers": "#AEC7E8",
    "Microsoft.Logic/workflows": "#FF9896",
    "Microsoft.DataFactory/factories": "#C5B0D5",
    "ResourceGroup": "#808080",
    "Subscription": "#FFD700",
    "SystemAssignedManagedIdentity": "#98df8a",
    "UserAssignedManagedIdentity": "#FF7F0E",
    "Principal": "#ffc5c2",
    "FederatedCredential": "#9edae5"
}


##############################################################################
#                           HELPER: RUN AZ CLI COMMANDS
##############################################################################
class AzureCLI:
    @staticmethod
    def run_az_cli(command: str):
        """
        Runs a shell command with Azure CLI and returns the parsed JSON or raw string.
        If an error occurs or the command exits with a non-zero code, returns an empty list.
        """
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"[ERROR] Command failed ({result.returncode}): {command}\n{result.stderr}")
                return []
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return result.stdout
        except Exception as e:
            print(f"Exception while running command: {e}")
            return []

##############################################################################
#                     DATA LOADER: FETCH RESOURCES VIA GRAPH
##############################################################################
class AzureGraphDataLoader:
    def __init__(self, cli: AzureCLI):
        self.cli = cli

    def fetch_subscription_resources(self, subscription_id: str, resource_types: List[str]) -> List[dict]:
        """
        For each resource type, run a filtered Resource Graph query.
        This helps ensure that each query returns fewer than 1000 rows.
        """
        all_resources = []
        with ThreadPoolExecutor() as executor:
            futures = []
            for rtype in resource_types:
                # Normalize the resource type to lowercase for comparison
                normalized_rtype = rtype.lower()
                # Construct the query to fetch resources of the specified type
                query = (
                    f"az graph query -q \"Resources | where tolower(type) =~ '{normalized_rtype}' | "
                    "project id, name, type, resourceGroup, subscriptionId, identity\" "
                    f"--subscriptions {subscription_id} --output json"
                )
                futures.append(executor.submit(self.cli.run_az_cli, query))
            
            for future in as_completed(futures):
                result = future.result()
                if isinstance(result, dict):
                    resources = result.get("data", [])
                elif isinstance(result, list):
                    resources = result
                else:
                    print(f"[WARNING] Unexpected result type for subscription {subscription_id}: {type(result)}")
                    resources = []
                all_resources.extend(resources)
        print(f"[INFO] Retrieved {len(all_resources)} resources from subscription {subscription_id}")
        return all_resources

##############################################################################
#                      GRAPH BUILDER: CREATE NODES & EDGES
##############################################################################
class AzureGraphBuilder:
    def __init__(self):
        self.nodes = []
        self.edges = []
        self.node_set = set()  # to deduplicate nodes by ID
        self.edge_set = set()  # to deduplicate edges by (source, target, label)

    def add_node(self, node_id: str, label: str, node_type: str, color: str = None):
        if node_id not in self.node_set:
            self.node_set.add(node_id)
            self.nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type,
                "color": color or RESOURCE_COLORS.get(node_type, "#1f77b4")
            })

    def update_node_label(self, node_id: str, new_label: str):
        """Update the label of an existing node (if present)."""
        for node in self.nodes:
            if node["id"] == node_id:
                node["label"] = new_label
                break

    def add_edge(self, source: str, target: str, label: str, color: str = "black"):
        key = (source, target, label)
        if key not in self.edge_set:
            self.edge_set.add(key)
            self.edges.append({
                "source": source,
                "target": target,
                "label": label,
                "color": color
            })

    def build_graph(self, resources: List[dict], subscription_id: str, subscription_name: str, resource_types: List[str]):
        # Create a subscription node.
        sub_node = f"/subscriptions/{subscription_id}"
        self.add_node(sub_node, subscription_name, "Subscription", RESOURCE_COLORS.get("Subscription"))
        
        # Keep track of processed resource groups so we add them only once.
        processed_rgs = set()
        
        for res in resources:
            res_id = res.get("id")
            res_name = res.get("name")
            res_type = res.get("type")
            rg = res.get("resourceGroup")
            if not (res_id and res_name and res_type and rg):
                continue
            
            # Filter only resource types we care about.
            if res_type.lower() not in [t.lower() for t in resource_types]:
                continue
            
            # Add resource group node (if not added already) and link it to the subscription.
            rg_node = f"/subscriptions/{subscription_id}/resourceGroups/{rg}"
            if rg_node not in processed_rgs:
                self.add_node(rg_node, rg, "ResourceGroup", RESOURCE_COLORS.get("ResourceGroup"))
                self.add_edge(sub_node, rg_node, "Contains", "#7f7f7f")
                processed_rgs.add(rg_node)
            
            # Determine a matching type (to pick the right color).
            matched_type = next((t for t in RESOURCE_COLORS if t.lower() == res_type.lower()), res_type)
            self.add_node(res_id, res_name, matched_type, RESOURCE_COLORS.get(matched_type, "#1f77b4"))
            self.add_edge(rg_node, res_id, "Contains", RESOURCE_COLORS.get(matched_type, "#1f77b4"))
            
            # Process identity blocks if available.
            identity = res.get("identity")
            if identity:
                id_type = identity.get("type", "")
                # Process SystemAssigned Identity.
                if "SystemAssigned" in id_type:
                    sys_pid = identity.get("principalId")
                    if sys_pid:
                        sys_node = f"{res_id}/systemAssigned"
                        self.add_node(sys_node, "SystemAssignedMI", "SystemAssignedManagedIdentity",
                                      RESOURCE_COLORS.get("SystemAssignedManagedIdentity"))
                        self.add_edge(res_id, sys_node, "Has SystemAssigned", "#98df8a")
                        # Link system-assigned identity to a principal node.
                        self.add_node(sys_pid, sys_pid, "Principal", RESOURCE_COLORS.get("Principal"))
                        self.add_edge(sys_node, sys_pid, "Linked", "blue")
                # Process UserAssigned Identities.
                if "UserAssigned" in id_type:
                    user_ids = identity.get("userAssignedIdentities", {})
                    for uami_id, uami_info in user_ids.items():
                        uami_name = uami_id.split("/")[-1]
                        self.add_node(uami_id, uami_name, "UserAssignedManagedIdentity",
                                      RESOURCE_COLORS.get("UserAssignedManagedIdentity"))
                        self.add_edge(res_id, uami_id, "Uses UAMI", "#ff7f0e")
                        uami_pid = uami_info.get("principalId")
                        if uami_pid:
                            self.add_node(uami_pid, uami_pid, "Principal", RESOURCE_COLORS.get("Principal"))
                            self.add_edge(uami_id, uami_pid, "Linked", "blue")

    def export(self, filename: str = "output_azure_resource_data.json"):
        data = {"nodes": self.nodes, "edges": self.edges}
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[INFO] Data exported to {filename}")

##############################################################################
#              RBAC PROCESSOR: ADD ROLE ASSIGNMENT EDGES
##############################################################################
class AzureRBACProcessor:
    def __init__(self, cli: AzureCLI, builder: AzureGraphBuilder):
        self.cli = cli
        self.builder = builder
        self.principal_name_cache = {}  # Cache for principal display names
        # Maintain mappings of scope -> set of (principal, role) assignments
        self.subscription_assignments = {}
        self.rg_assignments = {}
        self.resource_assignments = {}

    def resolve_principal_name(self, principal_id: str, assignment: Dict) -> str:
        """
        Use the role assignment's principalName if available and not a URL.
        If it's not a friendly name and a clientId is present (for Managed Identities),
        then query using the clientId. Otherwise, fall back to the previous resolution.
        """
        p_name = assignment.get("principalName")
        # If a principalName is provided and doesn't equal the ID, and is not a URL, use it.
        if p_name and isinstance(p_name, str) and p_name.strip() and p_name.strip() != principal_id and not p_name.strip().startswith("http"):
            return p_name.strip()
        # Check for a clientId.
        client_id = assignment.get("clientId")
        if client_id and isinstance(client_id, str) and client_id.strip():
            cmd_sp = f"az ad sp show --id {client_id} --query displayName --output tsv"
            result = self.cli.run_az_cli(cmd_sp)
            if isinstance(result, str) and result.strip():
                name = result.strip()
                self.principal_name_cache[principal_id] = name
                return name
        if principal_id in self.principal_name_cache:
            return self.principal_name_cache[principal_id]
        # Fallback resolution using principalId.
        cmd_user = f"az ad user show --id {principal_id} --query displayName --output tsv"
        result = self.cli.run_az_cli(cmd_user)
        if isinstance(result, str) and result.strip():
            name = result.strip()
            self.principal_name_cache[principal_id] = name
            return name
        cmd_sp = f"az ad sp show --id {principal_id} --query displayName --output tsv"
        result = self.cli.run_az_cli(cmd_sp)
        if isinstance(result, str) and result.strip():
            name = result.strip()
            self.principal_name_cache[principal_id] = name
            return name
        cmd_group = f"az ad group show --group {principal_id} --query displayName --output tsv"
        result = self.cli.run_az_cli(cmd_group)
        if isinstance(result, str) and result.strip():
            name = result.strip()
            self.principal_name_cache[principal_id] = name
            return name
        # If all else fails, return the principal ID.
        self.principal_name_cache[principal_id] = principal_id
        return principal_id

    def get_rbac_assignments(self, scope: str) -> List[Dict]:
        cmd = f'az role assignment list --scope "{scope}" --output json'
        result = self.cli.run_az_cli(cmd)
        if isinstance(result, list):
            return result
        elif isinstance(result, dict):
            return result.get("data", [])
        return []

    def process_subscription(self, sub_scope: str):
        assignments = self.get_rbac_assignments(sub_scope)
        sub_set = set()
        for a in assignments:
            principal = a.get("principalId")
            role = a.get("roleDefinitionName")
            if principal and role:
                sub_set.add((principal, role))
                display_name = self.resolve_principal_name(principal, a)
                self.builder.update_node_label(principal, display_name)
                self.builder.add_node(principal, display_name, "Principal", RESOURCE_COLORS.get("Principal"))
                self.builder.add_edge(principal, sub_scope, role, "#d62728")
        self.subscription_assignments[sub_scope] = sub_set

    def process_resource_group(self, rg_scope: str, sub_scope: str):
        assignments = self.get_rbac_assignments(rg_scope)
        rg_set = set()
        parent_set = self.subscription_assignments.get(sub_scope, set())
        for a in assignments:
            principal = a.get("principalId")
            role = a.get("roleDefinitionName")
            if principal and role:
                if (principal, role) not in parent_set:
                    rg_set.add((principal, role))
                    display_name = self.resolve_principal_name(principal, a)
                    self.builder.update_node_label(principal, display_name)
                    self.builder.add_node(principal, display_name, "Principal", RESOURCE_COLORS.get("Principal"))
                    self.builder.add_edge(principal, rg_scope, role, "#d62728")
        self.rg_assignments[rg_scope] = rg_set

    def process_resource(self, resource_scope: str, rg_scope: str, sub_scope: str):
        assignments = self.get_rbac_assignments(resource_scope)
        res_set = set()
        parent_rg = self.rg_assignments.get(rg_scope, set())
        parent_sub = self.subscription_assignments.get(sub_scope, set())
        parent = parent_rg.union(parent_sub)
        for a in assignments:
            principal = a.get("principalId")
            role = a.get("roleDefinitionName")
            if principal and role:
                if (principal, role) not in parent:
                    res_set.add((principal, role))
                    display_name = self.resolve_principal_name(principal, a)
                    self.builder.update_node_label(principal, display_name)
                    self.builder.add_node(principal, display_name, "Principal", RESOURCE_COLORS.get("Principal"))
                    self.builder.add_edge(principal, resource_scope, role, "#d62728")
        self.resource_assignments[resource_scope] = res_set

    def process_all(self):
        # Process subscriptions.
        with ThreadPoolExecutor() as executor:
            futures = []
            for node in self.builder.nodes:
                if node["type"] == "Subscription":
                    sub_scope = node["id"]
                    print(f"[INFO] Processing RBAC for subscription: {sub_scope}")
                    futures.append(executor.submit(self.process_subscription, sub_scope))
            for future in as_completed(futures):
                future.result()
        
        # Process resource groups.
        with ThreadPoolExecutor() as executor:
            futures = []
            for node in self.builder.nodes:
                if node["type"] == "ResourceGroup":
                    rg_scope = node["id"]
                    parts = rg_scope.split("/")
                    sub_scope = f"/subscriptions/{parts[2]}" if len(parts) > 2 else ""
                    print(f"[INFO] Processing RBAC for resource group: {rg_scope}")
                    futures.append(executor.submit(self.process_resource_group, rg_scope, sub_scope))
            for future in as_completed(futures):
                future.result()
        
        # Process resources.
        with ThreadPoolExecutor() as executor:
            futures = []
            for node in self.builder.nodes:
                if node["type"] not in ["Subscription", "ResourceGroup", "SystemAssignedManagedIdentity",
                                        "UserAssignedManagedIdentity", "Principal", "FederatedCredential"]:
                    resource_scope = node["id"]
                    rg_scope = None
                    for edge in self.builder.edges:
                        if edge["target"] == resource_scope:
                            parent_node = next((n for n in self.builder.nodes if n["id"] == edge["source"]), None)
                            if parent_node and parent_node["type"] == "ResourceGroup":
                                rg_scope = parent_node["id"]
                                break
                    if not rg_scope:
                        continue
                    parts = rg_scope.split("/")
                    sub_scope = f"/subscriptions/{parts[2]}" if len(parts) > 2 else ""
                    print(f"[INFO] Processing RBAC for resource: {resource_scope}")
                    futures.append(executor.submit(self.process_resource, resource_scope, rg_scope, sub_scope))
            for future in as_completed(futures):
                future.result()

##############################################################################
#                              MAIN EXECUTION
##############################################################################
if __name__ == "__main__":
    RESOURCE_TYPES = [
        "Microsoft.Subscription/subscriptions",
        "Microsoft.Resources/resourceGroups",
        "Microsoft.Compute/virtualMachines",
        "Microsoft.Compute/virtualMachineScaleSets",
        "Microsoft.Storage/storageAccounts",
        "Microsoft.KeyVault/vaults",
        "Microsoft.Web/sites",
        "Microsoft.ManagedIdentity/userAssignedIdentities",
        "Microsoft.ContainerService/managedClusters",
        "Microsoft.Automation/automationAccounts",
        "Microsoft.DocumentDB/databaseAccounts",
        "Microsoft.Sql/servers",
        "Microsoft.Logic/workflows",
        "Microsoft.DataFactory/factories"
    ]

    cli = AzureCLI()
    loader = AzureGraphDataLoader(cli)
    builder = AzureGraphBuilder()

    # Fetch subscriptions and process each one.
    subscriptions = cli.run_az_cli("az account list --output json")
    if subscriptions:
        with ThreadPoolExecutor() as executor:
            futures = []
            for sub in subscriptions:
                sub_id = sub.get("id")
                sub_name = sub.get("name", sub_id)
                print(f"[INFO] Processing subscription: {sub_name} ({sub_id})")
                futures.append(executor.submit(loader.fetch_subscription_resources, sub_id, RESOURCE_TYPES))
            
            for future in as_completed(futures):
                resources = future.result()
                sub_id = subscriptions[futures.index(future)]["id"]
                sub_name = subscriptions[futures.index(future)].get("name", sub_id)
                builder.build_graph(resources, sub_id, sub_name, RESOURCE_TYPES)
    else:
        print("[ERROR] No subscriptions found.")

    # Process RBAC assignments.
    rbac_processor = AzureRBACProcessor(cli, builder)
    rbac_processor.process_all()

    # Export the final graph data.
    builder.export("output_azure_resource_data4.json")
