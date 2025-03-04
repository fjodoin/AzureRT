import React, { useState } from "react";

const RESOURCE_COLORS = {
  "Subscriptions": "#bcbd22", // Microsoft.Subscription/subscriptions
  "ResourceGroups": "#7f7f7f", // Microsoft.Resources/resourceGroups
  "Virtual Machines": "#1f77b4", // Microsoft.Compute/virtualMachines
  "VM Scale Sets": "#aec7e8", // Microsoft.Compute/virtualMachineScaleSets
  "Storage Accounts": "#2ca02c", // Microsoft.Storage/storageAccounts
  "Key Vaults": "#9467bd", // Microsoft.KeyVault/vaults
  "App Services": "#e377c2", // Microsoft.Web/sites
  "User-Assigned Identities": "#ff7f0e", // Microsoft.ManagedIdentity/userAssignedIdentities
  "AKS": "#17becf", // Microsoft.ContainerService/managedClusters
  "Automation Accounts": "#8c564b", // Microsoft.Automation/automationAccounts
  "Cosmos DB": "#dbdb8d", // Microsoft.DocumentDB/databaseAccounts
  "Azure SQL": "#f7b6d2", // Microsoft.Sql/servers
  "Logic Apps": "#ff9896", // Microsoft.Logic/workflows
  "Data Factory": "#c49c94", // Microsoft.DataFactory/factories
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
