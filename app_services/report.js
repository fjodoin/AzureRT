document.addEventListener("DOMContentLoaded", () => {
    let sortedData = [...appServices];
    let currentSort = { key: null, order: "asc" };

    // Generate a unique ID for each app service.
    function getUID(app, index) {
        return app.name ? app.name + "-" + index : index;
    }

    // Extract sortable values for a given key.
    function getSortValue(app, key) {
        switch (key) {
            case "subscription_id":
                return app.subscription_id || "";
            case "resource_group":
                return app.resource_group || "";
            case "name":
                return app.name || "";
            case "location":
                return app.location || "";
            case "default_host_name":
                return app.default_host_name || "";
            case "state":
                return app.state || "";
            case "managed_identity_type":
                return app.managed_identity_type || "";
            case "managed_identity_ids":
                return app.managed_identity_ids || "";
            case "app_type":
                return app.app_type || "";
            default:
                return "";
        }
    }

    // Compare values for sorting.
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

    // Render the report table.
    function renderReport(data) {
        const container = document.getElementById("report-container");
        let html = `<table id="app-services-table">
                        <thead>
                          <tr>`;
        // Define table headers.
        const headers = [
            { label: "Subscription ID", key: "subscription_id" },
            { label: "Resource Group", key: "resource_group" },
            { label: "Name", key: "name" },
            { label: "Location", key: "location" },
            { label: "Default Host Name", key: "default_host_name" },
            { label: "State", key: "state" },
            { label: "Managed Identity", key: "managed_identity_type" },
            { label: "Managed Identity IDs", key: "managed_identity_ids" },
            { label: "Type", key: "app_type" }
        ];
        headers.forEach(header => {
            let arrow = "";
            if (currentSort.key === header.key) {
                arrow = currentSort.order === "asc" ? " ▲" : " ▼";
            }
            html += `<th data-key="${header.key}">${header.label}${arrow}</th>`;
        });
        html += `     </tr>
                    </thead>
                    <tbody>`;
        // Build rows for each app service.
        data.forEach((app, index) => {
            const uid = getUID(app, index);
            html += `<tr class="report-row" data-uid="${uid}" style="cursor:pointer;">
                        <td>${app.subscription_id || "N/A"}</td>
                        <td>${app.resource_group || "N/A"}</td>
                        <td>${app.name || "N/A"}</td>
                        <td>${app.location || "N/A"}</td>
                        <td>${app.default_host_name || "N/A"}</td>
                        <td>${app.state || "N/A"}</td>
                        <td>${app.managed_identity_type || "N/A"}</td>
                        <td>${app.managed_identity_ids || "N/A"}</td>
                        <td>${app.app_type || "N/A"}</td>
                     </tr>`;
            // Create a hidden details row.
            let detailsHtml = `<table class="container-details-table">
                                    <tbody>`;
            for (let key in app) {
                detailsHtml += `<tr>
                                    <td class="detail-key">${key}</td>
                                    <td class="detail-value">${app[key]}</td>
                                </tr>`;
            }
            detailsHtml += `   </tbody>
                              </table>`;
            html += `<tr class="details-row" data-uid="${uid}" style="display:none;">
                        <td colspan="9">${detailsHtml}</td>
                     </tr>`;
        });
        html += `   </tbody>
                  </table>`;
        container.innerHTML = html;

        // Attach event listeners for sorting.
        const headerCells = container.querySelectorAll("th[data-key]");
        headerCells.forEach(cell => {
            cell.addEventListener("click", function () {
                const key = this.getAttribute("data-key");
                if (currentSort.key === key) {
                    currentSort.order = currentSort.order === "asc" ? "desc" : "asc";
                } else {
                    currentSort.key = key;
                    currentSort.order = "asc";
                }
                sortedData.sort((a, b) => {
                    const aVal = getSortValue(a, key);
                    const bVal = getSortValue(b, key);
                    return compareValues(aVal, bVal, currentSort.order);
                });
                renderReport(sortedData);
            });
        });

        // Attach event listeners to toggle details.
        const rows = container.querySelectorAll(".report-row");
        rows.forEach(row => {
            row.addEventListener("click", function () {
                const uid = this.getAttribute("data-uid");
                const detailsRow = container.querySelector(`.details-row[data-uid="${uid}"]`);
                if (detailsRow) {
                    detailsRow.style.display = detailsRow.style.display === "none" ? "table-row" : "none";
                }
            });
        });
    }

    renderReport(sortedData);
});
