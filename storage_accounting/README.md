# storage_accounting.py  
**(Python 3+) Generate an interactive HTML file to investigate 🪣 Storage Accounts 🪣**  
> [!NOTE]  
> - Compatible with any platform that supports Python 3
> - Azure Python3 SDK 🐍
> - Requires "Reader" on in-scope Subscription, Resource Group, and or Storage Accounts (firewall restrictions may cause friction if launched as a non-Contribitor)

---
## Overview  
The `storage_accounting.py` script is designed to scan your Azure subscriptions for storage accounts and their containers, then generate an interactive HTML report to help you investigate security and access configurations. It leverages Azure CLI for authentication and API calls, providing a visual dashboard that highlights key metrics such as total storage accounts, public versus private access, and container-level details.

---

## Features  
- **Azure CLI Authentication:** Automatically authenticates using your Azure CLI credentials.
- **Subscription & Resource Scanning:** Retrieves storage account details across all accessible subscriptions.
- **Container Inspection:** Lists blob containers along with their public access settings.
- **Interactive HTML Report:** Generates an HTML file featuring sortable tables, filters, pagination, and detailed views.
- **Visual Dashboard:** Displays key statistics including totals for storage accounts, public/private status, and container access levels.

---

## Prerequisites  
- **Python 3:** Ensure Python 3 is installed on your system.
- **Azure CLI:** Must be installed and logged in (use `az login` to authenticate).
- **Azure Role Permissions:** Requires at least Reader permissions on the targeted subscriptions, resource groups, and storage accounts.

---

## Installation  
**Clone the Repository & Install Dependencies:**  
   ```bash
   git clone https://github.com/yourusername/storage_accounting.git
   cd storage_accounting
   # ACTIVATE your venv
   python3 -m pip install requests
   ```
   
## Run
```bash
python3 storage_accounting.py
python3 storage_accounting.py --output my_storage_report.html
```

## Investigate
- Open the HTML in your favorite browser
![image](https://github.com/user-attachments/assets/13bd3ca7-b3cb-47fc-a8e0-2f003480f22c)

