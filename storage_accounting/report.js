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
        case "publicNetworkAccess":
          return properties.publicNetworkAccess || "";
        case "allowBlobPublicAccess":
          if (typeof properties.allowBlobPublicAccess === "boolean") {
            return properties.allowBlobPublicAccess ? "Enabled" : "Disabled";
          }
          return "";
        case "containerCount":
          return account.containers ? account.containers.length : 0;
        case "risk": {
          let riskVal = "None";
          if (
            properties.publicNetworkAccess &&
            properties.publicNetworkAccess.toLowerCase() === "enabled"
          ) {
            if (
              account.containers &&
              account.containers.some(
                c =>
                  c.properties &&
                  c.properties.publicAccess &&
                  c.properties.publicAccess.toLowerCase() !== "none"
              )
            ) {
              riskVal = "High Risk";
            }
          }
          return riskVal;
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
        const publicNetworkAccess = properties.publicNetworkAccess || "Unknown";
        const allowBlobPublicAccess =
          typeof properties.allowBlobPublicAccess === "boolean"
            ? (properties.allowBlobPublicAccess ? "Enabled" : "Disabled")
            : "Unknown";
        const containerCount = account.containers ? account.containers.length : 0;
        // Calculate risk: if public network access is enabled and at least one container is public.
        let risk = "None";
        if (
          properties.publicNetworkAccess &&
          properties.publicNetworkAccess.toLowerCase() === "enabled"
        ) {
          if (
            account.containers &&
            account.containers.some(
              c =>
                c.properties &&
                c.properties.publicAccess &&
                c.properties.publicAccess.toLowerCase() !== "none"
            )
          ) {
            risk = "High Risk";
          }
        }
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
                   <td>${risk === "High Risk" ? '<span class="risk-tag">High Risk</span>' : risk}</td>
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
  