#!/bin/bash

echo "Scanning for secrets in JSON files..."

# Get all staged JSON files
files=$(git diff --cached --name-only --diff-filter=ACM | grep '\.json$')

if [ -z "$files" ]; then
    echo "No JSON files to scan."
    exit 0
fi

found_secrets=false
secret_details=""

for file in $files; do
    echo "Checking: $file"
    
    file_content=$(git show ":$file" 2>/dev/null)
    
    if [ -z "$file_content" ]; then
        echo "Warning: Could not read $file"
        continue
    fi
    
    # ========================================
    # Pattern 1: headerParametersJson with escaped quotes
    # Example: \"X-API-KEY\":\"actual_key_value\"
    # ========================================
    
    if echo "$file_content" | grep -E '(\\"|")X-API-KEY(\\"|")[[:space:]]*:[[:space:]]*(\\"|")[A-Za-z0-9]{20,}' > /dev/null; then
        if ! echo "$file_content" | grep -E '(\\"|")X-API-KEY(\\"|")[[:space:]]*:[[:space:]]*(\\"|")(YOUR_|PLACEHOLDER|<|xxx)' > /dev/null; then
            secret_details+="File: $file\n"
            secret_details+="   Issue: X-API-KEY found in headerParametersJson\n\n"
            found_secrets=true
        fi
    fi
    
    if echo "$file_content" | grep -E '(\\"|")X-API-SECRET(\\"|")[[:space:]]*:[[:space:]]*(\\"|")[A-Za-z0-9]{20,}' > /dev/null; then
        if ! echo "$file_content" | grep -E '(\\"|")X-API-SECRET(\\"|")[[:space:]]*:[[:space:]]*(\\"|")(YOUR_|PLACEHOLDER|<|xxx)' > /dev/null; then
            secret_details+="File: $file\n"
            secret_details+="   Issue: X-API-SECRET found in headerParametersJson\n\n"
            found_secrets=true
        fi
    fi
    
    if echo "$file_content" | grep -E '(\\"|")X-TIDENT(\\"|")[[:space:]]*:[[:space:]]*(\\"|")[A-Za-z0-9-]{20,}' > /dev/null; then
        if ! echo "$file_content" | grep -E '(\\"|")X-TIDENT(\\"|")[[:space:]]*:[[:space:]]*(\\"|")(YOUR_|PLACEHOLDER|<|xxx)' > /dev/null; then
            secret_details+="File: $file\n"
            secret_details+="   Issue: X-TIDENT found in headerParametersJson\n\n"
            found_secrets=true
        fi
    fi
    
    # ========================================
    # Pattern 2: Set node with values.string array
    # Example: "name": "x-api-key", "value": "actual_key_value"
    # ========================================
    
    # Check for x-api-key in Set node (case-insensitive)
    if echo "$file_content" | grep -iE '"name"[[:space:]]*:[[:space:]]*"x-api-key"' > /dev/null; then
        # Extract the value after the name
        value_line=$(echo "$file_content" | grep -iA2 '"name"[[:space:]]*:[[:space:]]*"x-api-key"' | grep '"value"')
        if echo "$value_line" | grep -E '"value"[[:space:]]*:[[:space:]]*"[A-Za-z0-9]{20,}"' > /dev/null; then
            if ! echo "$value_line" | grep -E '"value"[[:space:]]*:[[:space:]]*"(YOUR_|PLACEHOLDER|{{|\$node|<|xxx)' > /dev/null; then
                secret_details+="File: $file\n"
                secret_details+="   Issue: x-api-key found in Set node with actual value\n\n"
                found_secrets=true
            fi
        fi
    fi
    
    # Check for x-api-secret in Set node (case-insensitive)
    if echo "$file_content" | grep -iE '"name"[[:space:]]*:[[:space:]]*"x-api-secret"' > /dev/null; then
        value_line=$(echo "$file_content" | grep -iA2 '"name"[[:space:]]*:[[:space:]]*"x-api-secret"' | grep '"value"')
        if echo "$value_line" | grep -E '"value"[[:space:]]*:[[:space:]]*"[A-Za-z0-9]{20,}"' > /dev/null; then
            if ! echo "$value_line" | grep -E '"value"[[:space:]]*:[[:space:]]*"(YOUR_|PLACEHOLDER|{{|\$node|<|xxx)' > /dev/null; then
                secret_details+="File: $file\n"
                secret_details+="   Issue: x-api-secret found in Set node with actual value\n\n"
                found_secrets=true
            fi
        fi
    fi
    
    # Check for x-tident in Set node (case-insensitive)
    if echo "$file_content" | grep -iE '"name"[[:space:]]*:[[:space:]]*"x-tident"' > /dev/null; then
        value_line=$(echo "$file_content" | grep -iA2 '"name"[[:space:]]*:[[:space:]]*"x-tident"' | grep '"value"')
        if echo "$value_line" | grep -E '"value"[[:space:]]*:[[:space:]]*"[A-Za-z0-9-]{20,}"' > /dev/null; then
            if ! echo "$value_line" | grep -E '"value"[[:space:]]*:[[:space:]]*"(YOUR_|PLACEHOLDER|{{|\$node|<|xxx)' > /dev/null; then
                secret_details+="File: $file\n"
                secret_details+="   Issue: x-tident found in Set node with actual value\n\n"
                found_secrets=true
            fi
        fi
    fi
    
    # ========================================
    # Pattern 3: Generic "apiKey", "apiSecret", "password", "token"
    # ========================================
    
    if echo "$file_content" | grep -E '"(apiKey|api_key)"[[:space:]]*:[[:space:]]*"[A-Za-z0-9]{20,}"' > /dev/null; then
        if ! echo "$file_content" | grep -E '"(apiKey|api_key)"[[:space:]]*:[[:space:]]*"(YOUR_|PLACEHOLDER|<|xxx)' > /dev/null; then
            secret_details+="File: $file\n"
            secret_details+="   Issue: Generic apiKey found with actual value\n\n"
            found_secrets=true
        fi
    fi
    
    if echo "$file_content" | grep -E '"(apiSecret|api_secret)"[[:space:]]*:[[:space:]]*"[A-Za-z0-9]{20,}"' > /dev/null; then
        if ! echo "$file_content" | grep -E '"(apiSecret|api_secret)"[[:space:]]*:[[:space:]]*"(YOUR_|PLACEHOLDER|<|xxx)' > /dev/null; then
            secret_details+="File: $file\n"
            secret_details+="   Issue: Generic apiSecret found with actual value\n\n"
            found_secrets=true
        fi
    fi
    
    # ========================================
    # Pattern 4: Long hex strings (40+ characters)
    # Only flag if near credential-related keywords
    # ========================================
    
    if echo "$file_content" | grep -E '[a-f0-9]{36,}' > /dev/null; then
        # Check if this hex string is near credential keywords
        hex_context=$(echo "$file_content" | grep -B2 -A2 '[a-f0-9]{40,}')
        if echo "$hex_context" | grep -iE '(API|SECRET|KEY|TOKEN|TIDENT|AUTH|CREDENTIAL|PASSWORD)' > /dev/null; then
            # Exclude n8n expression syntax like {{$node["Set"].json["x-api-key"]}}
            if ! echo "$hex_context" | grep -E '({{|\$node|YOUR_|PLACEHOLDER)' > /dev/null; then
                secret_details+="File: $file\n"
                secret_details+="   Issue: Long hexadecimal string (40+ chars) near credential field\n\n"
                found_secrets=true
            fi
        fi
    fi
done

echo ""
if [ "$found_secrets" = true ]; then
    echo "========================================"
    echo "COMMIT BLOCKED - SECRETS DETECTED!"
    echo "========================================"
    echo -e "$secret_details"
    echo ""
    echo "How to fix:"
    echo ""
    echo "For headerParametersJson, use:"
    echo '  \"X-API-KEY\":\"YOUR_API_KEY_HERE\"'
    echo '  \"X-API-SECRET\":\"YOUR_API_SECRET_HERE\"'
    echo '  \"X-TIDENT\":\"YOUR_TENANT_ID_HERE\"'
    echo ""
    echo "For Set node values, use:"
    echo '  {"name": "x-api-key", "value": "YOUR_API_KEY_HERE"}'
    echo '  {"name": "x-api-secret", "value": "YOUR_API_SECRET_HERE"}'
    echo '  {"name": "x-tident", "value": "YOUR_TENANT_ID_HERE"}'
    echo ""
    echo "Or use n8n expressions to reference environment variables:"
    echo '  {"name": "x-api-key", "value": "={{$node[\"Set\"].json[\"x-api-key\"]}}"}'
    echo ""
    echo ""
    exit 1
else
    echo "No secrets detected. Commit approved."
    exit 0
fi