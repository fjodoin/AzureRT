#!/usr/bin/env python3
import argparse
import base64
import datetime
import hashlib
import hmac
import urllib.parse
import sys

def compute_signature(verb, resource_type, resource_link, date, key):
    """
    Computes the Cosmos DB authorization signature.
    
    The signature is computed over a string-to-sign which is constructed as:
      lower(verb) + "\n" +
      lower(resource_type) + "\n" +
      resource_link + "\n" +
      lower(rfc1123-date) + "\n\n"
      
    Parameters:
      verb (str): The HTTP method (e.g., GET).
      resource_type (str): The type of resource (e.g., 'dbs', 'colls', 'docs').
      resource_link (str): The relative resource link.
      date (str): The current date in RFC1123 format.
      key (str): The Base64 encoded account key.
      
    Returns:
      str: The URL encoded signature.
    """
    # Construct the string-to-sign by concatenating the lower-case values
    string_to_sign = f"{verb.lower()}\n{resource_type.lower()}\n{resource_link}\n{date.lower()}\n\n"
    
    # Decode the base64 account key to get raw bytes
    key_bytes = base64.b64decode(key)
    
    # Create an HMAC using SHA256 over the string-to-sign
    signature = hmac.new(key_bytes, msg=string_to_sign.encode('utf-8'), digestmod=hashlib.sha256).digest()
    
    # Encode the signature back into Base64 string
    signature_encoded = base64.b64encode(signature).decode()
    
    # URL encode the signature to ensure safe transmission in the HTTP header
    return urllib.parse.quote(signature_encoded)

def parse_connection_string(conn_str):
    """
    Parses the Cosmos DB connection string into its component parts.
    
    The connection string is expected to have key=value pairs separated by semicolons.
    
    Parameters:
      conn_str (str): The connection string.
      
    Returns:
      dict: A dictionary containing the connection string components.
    """
    parts = {}
    # Split the connection string by ';' and process each part
    for part in conn_str.split(';'):
        if part.strip():  # Ignore any empty segments
            key, value = part.split('=', 1)
            parts[key] = value
    return parts

def main():
    # Set up the argument parser with a description of the tool
    parser = argparse.ArgumentParser(
        description="Generate a curl command for various Cosmos DB operations using a connection string."
    )
    # Required connection string argument
    parser.add_argument(
        '--connection-string',
        required=True,
        help="Cosmos DB connection string, e.g., 'AccountEndpoint=https://your-account.documents.azure.com:443/;AccountKey=...;'"
    )
    # Operation argument to select which API action to perform
    parser.add_argument(
        '--operation',
        choices=['list-dbs', 'list-colls', 'list-docs'],
        required=True,
        help="Operation to perform: 'list-dbs' to list databases, 'list-colls' to list collections in a database, 'list-docs' to list documents in a collection."
    )
    # Optional database argument; required for some operations
    parser.add_argument(
        '--database',
        help="Database name (required for 'list-colls' and 'list-docs')."
    )
    # Optional collection argument; required for listing documents
    parser.add_argument(
        '--collection',
        help="Collection name (required for 'list-docs')."
    )

    # Parse the command-line arguments
    args = parser.parse_args()

    # Parse the connection string into its parts
    conn_parts = parse_connection_string(args.connection_string)
    endpoint = conn_parts.get('AccountEndpoint')
    account_key = conn_parts.get('AccountKey')

    # Validate that both endpoint and account key are provided
    if not endpoint or not account_key:
        print("Error: The connection string must contain both AccountEndpoint and AccountKey.")
        sys.exit(1)

    # Remove any trailing slash from the endpoint URL to avoid double slashes later
    endpoint = endpoint.rstrip('/')

    # Default HTTP method for Cosmos DB operations is GET
    verb = "GET"
    
    # Determine the resource type, resource link, and URL based on the selected operation.
    if args.operation == 'list-dbs':
        # Listing databases: no resource link is required
        resource_type = "dbs"
        resource_link = ""
        url = f"{endpoint}/dbs"
    elif args.operation == 'list-colls':
        # Listing collections requires a database name
        if not args.database:
            print("Error: --database is required for listing collections.")
            sys.exit(1)
        resource_type = "colls"
        resource_link = f"dbs/{args.database}"
        url = f"{endpoint}/dbs/{args.database}/colls"
    elif args.operation == 'list-docs':
        # Listing documents requires both a database and collection name
        if not args.database or not args.collection:
            print("Error: --database and --collection are required for listing documents.")
            sys.exit(1)
        resource_type = "docs"
        resource_link = f"dbs/{args.database}/colls/{args.collection}"
        url = f"{endpoint}/dbs/{args.database}/colls/{args.collection}/docs"
    else:
        print("Error: Invalid operation specified.")
        sys.exit(1)

    # Generate the current UTC time as a timezone-aware datetime object
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    # Format the date according to RFC1123 (required by Cosmos DB)
    x_ms_date = utc_now.strftime('%a, %d %b %Y %H:%M:%S GMT')

    # Compute the authorization signature using the helper function
    signature = compute_signature(verb, resource_type, resource_link, x_ms_date, account_key)
    # Build the full authorization header required by Cosmos DB
    auth_header = f"type=master&ver=1.0&sig={signature}"

    # Construct the curl command with all necessary headers for the operation
    curl_command = (
        f'curl -X {verb} "{url}" \\\n'
        f'  -H "Authorization: {auth_header}" \\\n'
        f'  -H "x-ms-date: {x_ms_date}" \\\n'
        f'  -H "x-ms-version: 2018-12-31"'
    )

    # Output the generated curl command to the console
    print("Generated curl command:")
    print(curl_command)

if __name__ == '__main__':
    # Execute the main function when the script is run directly
    main()
