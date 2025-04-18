document.addEventListener("DOMContentLoaded", () => {
    // Create a copy of the storageAccounts array to maintain the sorted data.
    let sortedData = [...storageAccounts];
    // Object to store the current sorting state.
    let currentSort = { key: null, order: "asc" };
  
    // Helper to get a unique identifier for each account.
    function getUID(account, index) {
      return account.id ? account.id : index;
    }
  
    // Helper function to extract sortable values based on a key.
    function getSortValue(account, key) {
      const properties = account.properties || {};
      switch (key) {
        case "name":
          return account.name || "";
        case "resourceGroup":
          return account.resourceGroup || "";
        case "subscriptionName":
          return account.subscriptionName || "";
        case "location":
          return account.location || "";
        case "publicNetworkAccess": {
          // Check various formats of publicNetworkAccess
          if (properties.publicNetworkAccess) {
            return properties.publicNetworkAccess;
          } else if (properties.networkAcls && properties.networkAcls.defaultAction) {
            // Some Azure APIs might return it through networkAcls
            return properties.networkAcls.defaultAction === "Allow" ? "Enabled" : "Disabled";
          }
          return "Unknown";
        }
        case "allowBlobPublicAccess":
          if (typeof properties.allowBlobPublicAccess === "boolean") {
            return properties.allowBlobPublicAccess ? "Enabled" : "Disabled";
          }
          return "Unknown";
        case "containerCount":
          return account.containers ? account.containers.length : 0;
        case "risk": {
          // Determine if public network access is enabled - check various formats
          let isPublicNetworkEnabled = false;
          
          if (properties.publicNetworkAccess) {
            // Direct property, regardless of case
            isPublicNetworkEnabled = properties.publicNetworkAccess.toLowerCase() === "enabled";
          } else if (properties.networkAcls && properties.networkAcls.defaultAction) {
            // Through networkAcls
            isPublicNetworkEnabled = properties.networkAcls.defaultAction.toLowerCase() === "allow";
          }
          
          if (isPublicNetworkEnabled) {
            // Start with Low Risk if public network is enabled
            let riskLevel = "Low Risk";
            
            // Check for Container access (High Risk) - always takes precedence
            if (account.containers && account.containers.some(
                c => c.properties && 
                    c.properties.publicAccess && 
                    c.properties.publicAccess.toLowerCase() === "container")) {
              riskLevel = "High Risk";
            }
            // Check for Blob access (Medium Risk) if not already High Risk
            else if (account.containers && account.containers.some(
                c => c.properties && 
                    c.properties.publicAccess && 
                    c.properties.publicAccess.toLowerCase() === "blob")) {
              riskLevel = "Medium Risk";
            }
            
            return riskLevel;
          }
          
          return "None";
        }
        default:
          return "";
      }
    }
  
    // Compare function for sorting.
    function compareValues(a, b, order = "asc") {
      if (!isNaN(a) && !isNaN(b)) {
        return order === "asc" ? a - b : b - a;
      } else {
        a = a.toString().toLowerCase();
        b = b.toString().toLowerCase();
        if (a < b) return order === "asc" ? -1 : 1;
        if (a > b) return order === "asc" ? 1 : -1;
        return 0;
      }
    }
  
    // Main function to render the report.
    function renderReport(data) {
      const container = document.getElementById("report-container");
      let html = `<table id="storage-accounts-table">
                    <thead>
                      <tr>`;
      // Define headers including the new Risk column.
      const headers = [
        { label: "Name", key: "name" },
        { label: "Resource Group", key: "resourceGroup" },
        { label: "Subscription", key: "subscriptionName" },
        { label: "Location", key: "location" },
        { label: "Public Network Access", key: "publicNetworkAccess" },
        { label: "Anonymous Access (Account)", key: "allowBlobPublicAccess" },
        { label: "Containers", key: "containerCount" },
        { label: "Risk", key: "risk" }
      ];
  
      // Build header row with sort arrows.
      headers.forEach(header => {
        let arrow = "";
        if (currentSort.key === header.key) {
          arrow = currentSort.order === "asc" ? " ▲" : " ▼";
        }
        html += `<th data-key="${header.key}">${header.label}${arrow}</th>`;
      });
      html += `   </tr>
                  </thead>
                  <tbody>`;
  
      // Build rows for each storage account.
      data.forEach((account, index) => {
        const properties = account.properties || {};
        
        // Determine public network access status
        let publicNetworkAccess = "Unknown";
        if (properties.publicNetworkAccess) {
          publicNetworkAccess = properties.publicNetworkAccess;
        } else if (properties.networkAcls && properties.networkAcls.defaultAction) {
          publicNetworkAccess = properties.networkAcls.defaultAction === "Allow" ? "Enabled" : "Disabled";
        }
        
        // Determine blob public access
        const allowBlobPublicAccess =
          typeof properties.allowBlobPublicAccess === "boolean"
            ? (properties.allowBlobPublicAccess ? "Enabled" : "Disabled")
            : "Unknown";
        
        const containerCount = account.containers ? account.containers.length : 0;
        
        // Calculate risk based on the enhanced requirements
        let risk = "None";
        
        // Determine if public network access is enabled
        let isPublicNetworkEnabled = false;
        if (properties.publicNetworkAccess) {
          isPublicNetworkEnabled = properties.publicNetworkAccess.toLowerCase() === "enabled";
        } else if (properties.networkAcls && properties.networkAcls.defaultAction) {
          isPublicNetworkEnabled = properties.networkAcls.defaultAction.toLowerCase() === "allow";
        }
        
        if (isPublicNetworkEnabled) {
          // Default to Low Risk if public network access is enabled
          risk = "Low Risk";
          
          if (account.containers && account.containers.length > 0) {
            // Check for Container level access (High Risk) - always takes precedence
            if (account.containers.some(
              c => c.properties && 
                  c.properties.publicAccess && 
                  c.properties.publicAccess.toLowerCase() === "container"
            )) {
              risk = "High Risk";
            }
            // Check for Blob level access (Medium Risk) - only if not already High Risk
            else if (account.containers.some(
              c => c.properties && 
                  c.properties.publicAccess && 
                  c.properties.publicAccess.toLowerCase() === "blob"
            )) {
              risk = "Medium Risk";
            }
          }
        }
        
        // Update the display based on risk level
        const riskDisplay = risk === "High Risk" 
          ? '<span class="risk-tag high-risk">High Risk</span>' 
          : (risk === "Medium Risk" 
            ? '<span class="risk-tag medium-risk">Medium Risk</span>' 
            : (risk === "Low Risk" 
                ? '<span class="risk-tag low-risk">Low Risk</span>' 
                : risk));
                
        // Use a unique ID for toggling details.
        const uid = getUID(account, index);
        html += `<tr class="account-row" data-uid="${uid}" style="cursor:pointer;">
                  <td>${account.name || "Unknown"}</td>
                  <td>${account.resourceGroup || "Unknown"}</td>
                  <td>${account.subscriptionName || "Unknown"}</td>
                  <td>${account.location || "Unknown"}</td>
                  <td>${publicNetworkAccess}</td>
                  <td>${allowBlobPublicAccess}</td>
                  <td>${containerCount}</td>
                  <td>${riskDisplay}</td>
                </tr>`;
  
        // Add a hidden details row if containers exist.
        if (containerCount > 0) {
          let containerDetailsHtml = `<table class="container-details-table">
                                        <thead>
                                          <tr>
                                            <th>Container Name</th>
                                            <th>Anonymous Access Level</th>
                                          </tr>
                                        </thead>
                                        <tbody>`;
          account.containers.forEach(cont => {
            const containerAccess =
              cont.properties && cont.properties.publicAccess ? cont.properties.publicAccess : "None";
            containerDetailsHtml += `<tr>
                                      <td>${cont.name}</td>
                                      <td>${containerAccess}</td>
                                    </tr>`;
          });
          containerDetailsHtml += `   </tbody>
                                      </table>`;
          html += `<tr class="details-row" data-uid="${uid}" style="display:none;">
                    <td colspan="8">${containerDetailsHtml}</td>
                  </tr>`;
        }
      });
      html += `   </tbody>
                </table>`;
      container.innerHTML = html;
  
      // Attach event listeners to header cells for sorting.
      const headerCells = container.querySelectorAll("th[data-key]");
      headerCells.forEach(cell => {
        cell.addEventListener("click", function () {
          const key = this.getAttribute("data-key");
          // Toggle order if the same column is clicked.
          if (currentSort.key === key) {
            currentSort.order = currentSort.order === "asc" ? "desc" : "asc";
          } else {
            currentSort.key = key;
            currentSort.order = "asc";
          }
          sortedData.sort((a, b) => {
            const aValue = getSortValue(a, key);
            const bValue = getSortValue(b, key);
            return compareValues(aValue, bValue, currentSort.order);
          });
          renderReport(sortedData);
        });
      });
  
      // Attach event listeners to account rows to toggle metadata display.
      attachRowToggle();
    }
  
    // Attach click event listeners for toggling the details row.
    function attachRowToggle() {
      document.querySelectorAll(".account-row").forEach(row => {
        row.addEventListener("click", function () {
          const uid = this.getAttribute("data-uid");
          const detailsRow = document.querySelector(`.details-row[data-uid="${uid}"]`);
          if (detailsRow) {
            detailsRow.style.display = detailsRow.style.display === "none" ? "table-row" : "none";
          }
        });
      });
    }
  
    // Initial render.
    renderReport(sortedData);
  });