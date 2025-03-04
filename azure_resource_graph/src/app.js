import React, { useState } from "react";
import GraphWrapper from "./GraphWrapper";
import Legend from "./Legend";
import "./app.css";

function App() {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("");
  const [graphData, setGraphData] = useState(null);

  const handleSearchChange = (event) => {
    setSearchQuery(event.target.value);
  };

  const handleCategoryChange = (event) => {
    setSelectedCategory(event.target.value);
  };

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const jsonData = JSON.parse(e.target.result);
          setGraphData(jsonData);
        } catch (error) {
          console.error("Error parsing JSON:", error);
          alert("Invalid JSON file.");
        }
      };
      reader.readAsText(file);
    }
  };

  return (
    <div className="App">
      <div className="header-row">
        <h1>🏴‍☠️ Azure Resource Graph (ARG) 🏴‍☠️</h1>
        <div className="controls">
          <input type="file" accept=".json" onChange={handleFileUpload} />
          <select className="category-dropdown" value={selectedCategory} onChange={handleCategoryChange}>
            <option value="">Select Category</option>
            <option value="Microsoft.ContainerService/managedClusters">AKS</option>
            <option value="Microsoft.Web/sites">App Services</option>
            <option value="Microsoft.Automation/automationAccounts">AutomationAccount</option>
            <option value="Microsoft.DocumentDB/databaseAccounts">CosmosDB</option>
            <option value="Microsoft.DataFactory/factories">Data Factory</option>
            <option value="FederatedCredential">FederatedCredential</option>
            <option value="Microsoft.KeyVault/vaults">KeyVault</option>
            <option value="Microsoft.Logic/workflows">Logic Apps</option>
            <option value="Microsoft.Sql/servers">Azure SQL</option>
            <option value="Microsoft.ManagedIdentity/userAssignedIdentities">UA-ManagedIdentity</option>
            <option value="Principal">Principal</option>
            <option value="ResourceGroup">ResourceGroup</option>
            <option value="Microsoft.Storage/storageAccounts">StorageAccount</option>
            <option value="Subscription">Subscription</option>
            <option value="SystemAssignedManagedIdentity">SA-ManagedIdentities</option>
            <option value="Microsoft.Compute/virtualMachines">VirtualMachine</option>
            <option value="Microsoft.Compute/virtualMachineScaleSets">VirtualMachineScaleSet</option>
          </select>
          <input type="text" className="search-box" placeholder="Search..." value={searchQuery} onChange={handleSearchChange} />
          <Legend />
        </div>
      </div>
      <div className="main-container">
        <GraphWrapper searchQuery={searchQuery} selectedCategory={selectedCategory} graphData={graphData} />
      </div>
    </div>
  );
}

export default App;
