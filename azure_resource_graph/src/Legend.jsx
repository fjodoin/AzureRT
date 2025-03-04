import React, { useState } from "react";

const RESOURCE_COLORS = {
  "Subscriptions": "#FFD700", // Gold (distinct and stands out for a top-level resource)
  "ResourceGroups": "#808080", // Gray (neutral for organizational resources)
  "Virtual Machines": "#1f77b4", // Azure Blue (classic Azure color)
  "VM Scale Sets": "#4E79A7", // Darker Blue (related to VMs but distinct)
  "Storage Accounts": "#2CA02C", // Green (represents storage and data)
  "Key Vaults": "#9467BD", // Purple (security-related, distinct)
  "App Services": "#E377C2", // Pink (for web/app-related services)
  "User-Assigned Identities": "#FF7F0E", // Orange (identity-related, distinct)
  "AKS": "#17BECF", // Cyan (modern, for container services)
  "Automation Accounts": "#8C564B", // Brown (unique for automation)
  "Cosmos DB": "#D62728", // Red (distinct for database services)
  "Azure SQL": "#AEC7E8", // Light Gray (neutral for SQL services)
  "Logic Apps": "#FF9896", // Light Coral (for workflow-related services)
  "Data Factory": "#C5B0D5", // Light Purple (for data integration services)
};

const Legend = () => {
  const [isVisible, setIsVisible] = useState(false);

  return (
    <>
      <button className="legend-toggle" onClick={() => setIsVisible(!isVisible)}>
        {isVisible ? "Hide Legend" : "Show Legend"}
      </button>

      <div className={`legend-container ${isVisible ? "visible" : "hidden"}`}>
        <h3>Legend</h3>
        <ul>
          {Object.entries(RESOURCE_COLORS).map(([resource, color]) => (
            <li key={resource} className="legend-item">
              <span className="legend-color" style={{ backgroundColor: color }}></span>
              <span className="legend-text">{resource}</span>
            </li>
          ))}
        </ul>
      </div>
    </>
  );
};

export default Legend;
