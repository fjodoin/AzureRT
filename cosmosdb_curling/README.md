# cosmosdb_nosql_curling.py  
**(Python 3+) Generate 🥌 curl commands 🥌 for CosmosDB operations**  
> [!NOTE]  
> - Compatible with any platform that supports Python 3
> - Only supports CosmosDB NoSQL for the moment  
> - Requires a valid CosmosDB connection string  
> - Supports multiple operations: listing databases, collections, and documents  

---

## Overview  
The `cosmosdb_nosql_curling.py` script is designed to generate curl commands for various Azure CosmosDB operations. It computes the necessary authorization headers from your CosmosDB connection string and supports three key operations:  
- **list-dbs**: List all databases in the CosmosDB account  
- **list-colls**: List all collections (containers) in a specified database  
- **list-docs**: List documents within a specified collection  

Using this script, you can quickly generate the appropriate curl command to interact with your CosmosDB account.

---

## Prerequisites  
To use this script, ensure you have the following:  

- **Python 3**: Make sure Python 3 is installed on your system  
- **CosmosDB Connection String**: A valid connection string containing both `AccountEndpoint` and `AccountKey`

---

## Usage  

1. **Clone the repository and navigate to the script directory**

   ```bash
   git clone https://github.com/fjodoin/AzureRT.git
   cd cosmosdb_curling
   ```

2. **Run the script with the required arguments**
- Assign variable:
    ```bash
    connection_string='AccountEndpoint=https://[...]'
    ```
- Operations:
    ```bash
    # List Databases    
   ./cosmosdb_nosql_curling.py --connection-string $connection_string --operation list-dbs
    
   # List Collections in a Database
   ./cosmosdb_nosql_curling.py --connection-string $connection_string --operation list-colls --database your-db

   # List Documents in a Collection
    ./cosmosdb_nosql_curling.py --connection-string $connection_string --operation list-docs --database your-db --collection your-coll
    ```

3. **Execute the generated curl command**
- The script will output a curl command with the required headers. Copy and execute it in your terminal to interact with your CosmosDB account.
