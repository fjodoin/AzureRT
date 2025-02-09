# Invoke-AzVMInfo.ps1  
**(PowerShell 7+) List Azure Virtual Machines with associated Public IP Addresses**
> [!NOTE]
> - Compatible with non-Windows PowerShell (pwsh)
> - Az SDK wrapper 🌯

---

## Overview  
The `Invoke-AzVMInfo.ps1` script is designed to automate the execution of commands across multiple Azure Virtual Machines (VMs). This script will use Role-Base Access Control (RBAC) access to query all VMs for associated Public IP addresses.  

## Prerequisites  
To use this script, you need the following:  

- **Az PowerShell SDK**: Authenticate with `Connect-AzAccount` before launching `Invoke-AzVMInfo.ps1`.
- **Azure RBAC Reader**: The identity to use with the `Az SDK` requires atleast "Reader" on the subscription(s), resource group(s), or resource(s) in-scope.
  
## Usage  

  ```powershell
  # 1. Clone or download this repository.
  git clone https://github.com/fjodoin/AzureRT.git

  # 2. Change into the according directory.
  cd ./AzureRT/Invoke-AzVMInfo

  # 3. Fire-up a PowerShell 7+ session  
  pwsh
  ```

  <img width="857" alt="image" src="https://github.com/user-attachments/assets/0b8fe56a-1446-4879-844d-cce20281fc94" />

  ```powershell
  # 4. Load the function 
  . .\Invoke-AzVMInfo.ps1

  # 5. Run the function
  Invoke-AzVMInfo
  ```

  ![image](https://github.com/user-attachments/assets/36358bdb-cd7a-4051-b3d7-f5951ebf9060)

  ```powershell
  # 6. Investigate your Azure VM network info report!
  ```

  ![image](https://github.com/user-attachments/assets/7d65dc25-3f87-4d0a-90e2-93e6a461cb84)



  
