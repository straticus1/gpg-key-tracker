# GPG Key Search API Guide

The GPG Key Server provides enhanced search capabilities including text search, specific field search, and raw key file validation.

## Search Endpoints

### 1. Enhanced Key Search

**Endpoint**: `POST /keys/search`

**Description**: Search for keys using various search types and fields.

#### Request Body

```json
{
  "query": "search term",
  "search_type": "text",
  "fields": ["email", "name"],
  "limit": 50
}
```

#### Search Types

- **`text`** (default): Search across all specified fields
- **`fingerprint`**: Search by fingerprint (partial or exact)
- **`key_id`**: Search by key ID
- **`email`**: Search by email address
- **`name`**: Search by name
- **`owner`**: Search by owner

#### Examples

**1. General text search:**
```bash
curl -X POST -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "john@example.com",
    "search_type": "text",
    "limit": 10
  }' \
  https://server:8443/keys/search
```

**2. Search by fingerprint:**
```bash
curl -X POST -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "ABCD1234",
    "search_type": "fingerprint",
    "limit": 10
  }' \
  https://server:8443/keys/search
```

**3. Search by email:**
```bash
curl -X POST -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "john@example.com",
    "search_type": "email",
    "limit": 10
  }' \
  https://server:8443/keys/search
```

**4. Search specific fields:**
```bash
curl -X POST -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "developer",
    "search_type": "text",
    "fields": ["name", "notes"],
    "limit": 20
  }' \
  https://server:8443/keys/search
```

### 2. Key Existence Check

**Endpoint**: `POST /keys/check`

**Description**: Check if a GPG key exists by uploading the key data. If the key doesn't exist, provides instructions on how to add it.

#### Request Body

```json
{
  "key_data": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
  "check_only": true
}
```

#### Examples

**Check if key exists:**
```bash
curl -X POST -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "key_data": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v2\n\nmQENBF...\n-----END PGP PUBLIC KEY BLOCK-----",
    "check_only": true
  }' \
  https://server:8443/keys/check
```

**Response for existing key:**
```json
{
  "found": true,
  "fingerprint": "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234",
  "key_info": {
    "id": 123,
    "fingerprint": "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234",
    "owner": "john@example.com",
    "name": "John Doe",
    "created_at": "2023-01-15T10:30:00Z"
  },
  "message": "Key ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234 is already in the system"
}
```

**Response for non-existing key:**
```json
{
  "found": false,
  "fingerprint": "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234",
  "message": "Key ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234 is not in the system",
  "how_to_add": {
    "method": "POST",
    "endpoint": "/keys",
    "description": "Add the key by sending key_data, owner, and requester information",
    "example_curl": "curl -X POST -H \"X-API-Key: YOUR_API_KEY\" -H \"Content-Type: application/json\" -d '{\"key_data\": \"YOUR_KEY_DATA\", \"owner\": \"owner@example.com\", \"requester\": \"requester@example.com\"}' https://server:8443/keys",
    "required_fields": ["key_data", "owner", "requester"],
    "optional_fields": ["jira_ticket", "notes"]
  }
}
```

## Search Permissions

All search operations require appropriate API key permissions:
- **Search permission**: Required for `/keys/search` and `/keys/check` endpoints
- **Key access**: API keys with limited key access (`keys: ["fingerprint1", "fingerprint2"]`) will only see results for keys they have access to
- **Wildcard access**: API keys with `keys: "*"` can search all keys

## Python Examples

### Using requests library

```python
import requests

# Search by email
def search_by_email(api_key, email, server_url="https://localhost:8443"):
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}

    data = {
        "query": email,
        "search_type": "email",
        "limit": 10
    }

    response = requests.post(f"{server_url}/keys/search",
                           headers=headers, json=data)

    if response.status_code == 200:
        return response.json()["keys"]
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return []

# Check if key exists
def check_key_exists(api_key, key_data, server_url="https://localhost:8443"):
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}

    data = {
        "key_data": key_data,
        "check_only": True
    }

    response = requests.post(f"{server_url}/keys/check",
                           headers=headers, json=data)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

# Usage examples
api_key = "your-api-key-here"

# Search for keys by email
keys = search_by_email(api_key, "john@example.com")
for key in keys:
    print(f"Found key: {key['fingerprint']} - {key['name']}")

# Check if a key exists
with open("public_key.asc", "r") as f:
    key_data = f.read()

result = check_key_exists(api_key, key_data)
if result:
    if result["found"]:
        print(f"Key found: {result['key_info']['name']}")
    else:
        print(f"Key not found. {result['message']}")
        if result.get("how_to_add"):
            print(f"To add: {result['how_to_add']['description']}")
```

## JavaScript/Node.js Examples

```javascript
const axios = require('axios');

// Search configuration
const config = {
    serverUrl: 'https://localhost:8443',
    apiKey: 'your-api-key-here'
};

// Search by fingerprint
async function searchByFingerprint(fingerprint) {
    try {
        const response = await axios.post(`${config.serverUrl}/keys/search`, {
            query: fingerprint,
            search_type: 'fingerprint',
            limit: 10
        }, {
            headers: {
                'X-API-Key': config.apiKey,
                'Content-Type': 'application/json'
            }
        });

        return response.data.keys;
    } catch (error) {
        console.error('Search error:', error.response?.data || error.message);
        return [];
    }
}

// Check key existence
async function checkKeyExists(keyData) {
    try {
        const response = await axios.post(`${config.serverUrl}/keys/check`, {
            key_data: keyData,
            check_only: true
        }, {
            headers: {
                'X-API-Key': config.apiKey,
                'Content-Type': 'application/json'
            }
        });

        return response.data;
    } catch (error) {
        console.error('Check error:', error.response?.data || error.message);
        return null;
    }
}

// Usage
searchByFingerprint('ABCD1234').then(keys => {
    keys.forEach(key => {
        console.log(`Found: ${key.fingerprint} - ${key.name}`);
    });
});
```

## Advanced Search Scenarios

### 1. Multi-term Search
For complex searches, use the text search type with multiple terms:

```bash
curl -X POST -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "john developer",
    "search_type": "text",
    "fields": ["name", "notes", "user_id"],
    "limit": 20
  }' \
  https://server:8443/keys/search
```

### 2. Batch Key Validation
For validating multiple keys, you can script multiple calls to the check endpoint:

```python
import requests
import glob

def validate_key_files(api_key, key_directory):
    results = []

    for key_file in glob.glob(f"{key_directory}/*.asc"):
        with open(key_file, 'r') as f:
            key_data = f.read()

        result = check_key_exists(api_key, key_data)
        results.append({
            'file': key_file,
            'found': result['found'] if result else False,
            'fingerprint': result.get('fingerprint') if result else None
        })

    return results

# Validate all .asc files in a directory
results = validate_key_files("your-api-key", "./keys")
for result in results:
    status = "EXISTS" if result['found'] else "NOT FOUND"
    print(f"{result['file']}: {status} ({result.get('fingerprint', 'N/A')})")
```

### 3. Permission-based Search Results
API keys with limited permissions will only see keys they have access to:

```bash
# API key with limited access to specific keys
curl -X POST -H "X-API-Key: limited-access-key" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "example.com",
    "search_type": "email",
    "limit": 100
  }' \
  https://server:8443/keys/search
```

The response will only include keys that the API key has permission to access based on its `permissions.keys` configuration.

## Error Handling

Common error responses:

```json
// 401 - Authentication required
{
  "error": "API key required"
}

// 403 - Insufficient permissions
{
  "error": "Insufficient permissions for operation: search"
}

// 422 - Validation error
{
  "error": "Validation Error",
  "detail": [
    {
      "loc": ["body", "search_type"],
      "msg": "Search type must be one of: ['text', 'fingerprint', 'key_id', 'email', 'name', 'owner']",
      "type": "value_error"
    }
  ]
}
```