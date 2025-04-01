# AzureRT  
**🔎 Azure Research Toolkit 🔬**  

---

![image](https://github.com/user-attachments/assets/8e68f06d-d2b4-4711-a326-9875818823d0)

---

## Introduction  
Azure Research Toolkit (AzureRT) is a collection of scripts designed to assist with **Offensive, Defensive, and Integrated Cloud Security** in the Azure. Whether you're conducting security assessments, reinforcing your cloud defenses, or integrating security practices across your Azure infrastructure, this repository provides tools to streamline your efforts.  

## Repository Contents  
Below is a table of tools and scripts included in this repository, along with their descriptions and links to their respective folders:  

|Tool/Script Name|Description|Link|
|---|---|---|
|**azure_resource_graph_collector.py**|Build an Azure Resource Graph to visualize blindspots e.g. Key Vault Access Policies|[azure_resource_graph](./azure_resource_graph)|
|**cosmosdb_curling.py**|CosmosDB API helper which will generate signatured curl commands|[cosmosdb_curling](./cosmosdb_curling)|
|**storage_accounting.py**|Find Azure Storage Account Containers and Blobs with Public Access|[storage_accounting](./storage_accounting)|
|**Invoke-AzRBACListCustomRoles.ps1**|Find Custom Azure RBAC Roles assigned across assets|[Invoke-AzRBACListCustomRoles](./Invoke-AzRBACListCustomRoles)|
|**Invoke-AzVMBulkRunCommand.ps1**|Automates bulk execution of commands across multiple Azure Virtual Machines|[Invoke-AzVMBulkRunCommand](./Invoke-AzVMBulkRunCommand)|
|**Invoke-AzVMInfo.ps1**|Generates an HTML report to visualize Azure Virtual Machines Network Info|[Invoke-AzVMInfo](./Invoke-AzVMInfo)|

---
> [!NOTE]
> **Disclaimer**
> - This Azure Research Toolkit is provided for educational and research purposes only. The authors are not responsible for any misuse or illegal application of this toolkit. Users are solely responsible for ensuring that their actions comply with all applicable laws, regulations, and terms of service.
> - This software is provided "as is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, or noninfringement. In no event shall the authors be liable for any claim, damages, or other liability arising from the use of this toolkit.
> - Use responsibly and only on systems you own or have explicit permission to test.
