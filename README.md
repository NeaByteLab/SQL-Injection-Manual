# SQL Injection Manual

Complete hands-on guide from beginner to expert level. This 22-chapter curriculum provides comprehensive coverage of SQL injection vulnerabilities across MySQL, PostgreSQL, MSSQL, Oracle, and SQLite.

## What You Will Learn

- **Detection & Fundamentals** - Systematic approaches to identify injection points through error messages, boolean logic, and time-based delays.

- **Data Extraction** - Master UNION-based extraction, blind injection with binary search optimization, schema enumeration, and efficient dumping techniques for large datasets.

- **Defense Evasion** - Advanced WAF bypass techniques including case variation, comment injection, double URL encoding, hex concatenation, REVERSE() function obfuscation, and cutting-edge JSON SQL operator bypasses (@>, <@, JSON_EXTRACT) that exploit parser mismatches.

- **Modern Attack Vectors** - Exploit JSON APIs, XML/SOAP services, HTTP headers, cookies, JWT KID parameters, GraphQL resolvers, and ORM frameworks (Hibernate, Django, Sequelize).

- **Specialized Techniques** - Second-order stored injection, HTTP Parameter Pollution, heavy query DoS attacks, polyglot XSS+SQLi payloads, multibyte encoding bypasses (GBK, Big5, Shift-JIS), and NoSQL injection (MongoDB, Redis, Cassandra, Elasticsearch).

- **System Compromise** - File system operations, privilege escalation, and OS command execution via database functions.

Each chapter includes real-world scenarios, database-specific syntax, exploitation workflows, detection checklists, and defensive mitigation strategies. The cheat sheet provides quick reference for all payloads across database types.

## Quick Navigation

| Order | File                                                                                   | Topic                        | Level        | Key Skills                                                       |
| ----- | -------------------------------------------------------------------------------------- | ---------------------------- | ------------ | ---------------------------------------------------------------- |
| 1     | [Guide/01-Introduction.md](Guide/01-Introduction.md)                                   | SQL Injection Fundamentals   | Beginner     | Understanding vulnerability, basic payloads, prevention          |
| 2     | [Guide/02-Detection-Methods.md](Guide/02-Detection-Methods.md)                         | Finding Injection Points     | Beginner     | Reconnaissance, testing methodology, tool usage                  |
| 3     | [Guide/03-Basic-Exploitation.md](Guide/03-Basic-Exploitation.md)                       | Error & Boolean Exploitation | Beginner     | Error-based extraction, blind boolean, time-based                |
| 4     | [Guide/04-Union-Injection.md](Guide/04-Union-Injection.md)                             | Union-Based Data Extraction  | Intermediate | Column enumeration, UNION SELECT, concatenation                  |
| 5     | [Guide/05-Database-Fingerprinting.md](Guide/05-Database-Fingerprinting.md)             | DB Identification            | Intermediate | Version detection, syntax differences, capabilities              |
| 6     | [Guide/06-Schema-Enumeration.md](Guide/06-Schema-Enumeration.md)                       | Database Mapping             | Advanced     | System tables, column extraction, blind enumeration              |
| 7     | [Guide/07-Data-Extraction.md](Guide/07-Data-Extraction.md)                             | Efficient Data Dumping       | Advanced     | GROUP_CONCAT, chunked extraction, optimization                   |
| 8     | [Guide/08-Blind-Injection.md](Guide/08-Blind-Injection.md)                             | Advanced Blind Techniques    | Intermediate | Binary search, automation, OOB extraction                        |
| 9     | [Guide/09-Filter-Evasion.md](Guide/09-Filter-Evasion.md)                               | WAF Bypass Techniques        | Expert       | Encoding, comments, keyword alternatives, tampering              |
| 10    | [Guide/10-Advanced-Techniques.md](Guide/10-Advanced-Techniques.md)                     | Stacked Queries & File Ops   | Expert       | Multi-statement execution, file read/write, privilege escalation |
| 11    | [Guide/11-OS-Command-Execution.md](Guide/11-OS-Command-Execution.md)                   | Shell Access via SQLi        | Expert       | UDF, xp_cmdshell, COPY TO PROGRAM, reverse shells                |
| 12    | [Guide/12-Second-Order-Injection.md](Guide/12-Second-Order-Injection.md)               | Stored Injection Attacks     | Expert       | Delayed execution, storage-based attacks, admin exploitation     |
| 13    | [Guide/13-Alternative-Context-Injection.md](Guide/13-Alternative-Context-Injection.md) | JSON, XML, Header Injection  | Expert       | Modern API contexts, HTTP headers, cookies                       |
| 14    | [Guide/14-HTTP-Parameter-Pollution.md](Guide/14-HTTP-Parameter-Pollution.md)           | HPP Attacks                  | Expert       | Duplicate parameter exploitation, framework bypass               |
| 15    | [Guide/15-Heavy-Query-DoS.md](Guide/15-Heavy-Query-DoS.md)                             | Resource Exhaustion          | Expert       | CPU/memory/disk exhaustion, DoS via SQL                          |
| 16    | [Guide/16-JWT-SQL-Injection.md](Guide/16-JWT-SQL-Injection.md)                         | JWT Injection                | Expert       | KID parameter SQL injection, signature bypass                    |
| 17    | [Guide/17-GraphQL-SQL-Injection.md](Guide/17-GraphQL-SQL-Injection.md)                 | GraphQL Injection            | Expert       | Resolver vulnerabilities, API-layer injection                    |
| 18    | [Guide/18-ORM-Injection.md](Guide/18-ORM-Injection.md)                                 | ORM Bypass Techniques        | Expert       | Hibernate, Django ORM, Sequelize bypasses                        |
| 19    | [Guide/19-Polyglot-Payloads.md](Guide/19-Polyglot-Payloads.md)                         | Polyglot Payloads            | Expert       | XSS+SQLi combo, multi-context payloads                           |
| 20    | [Guide/20-Multibyte-Encoding-Bypass.md](Guide/20-Multibyte-Encoding-Bypass.md)         | Multibyte Bypass             | Expert       | GBK/charset encoding bypasses                                    |
| 21    | [Guide/21-NoSQL-Injection.md](Guide/21-NoSQL-Injection.md)                             | NoSQL Injection              | Expert       | MongoDB, Redis, Cassandra, Elasticsearch injection               |
| 22    | [Guide/22-Cheat-Sheet.md](Guide/22-Cheat-Sheet.md)                                     | Complete Reference           | All Levels   | Quick payload reference, syntax comparison                       |

## Learning Path by Goal

### Goal 1: Detection & Basic Exploitation

Start here if you are new to SQL injection:

1. [Guide/01-Introduction.md](Guide/01-Introduction.md) - Understand the vulnerability
2. [Guide/02-Detection-Methods.md](Guide/02-Detection-Methods.md) - Learn to find injection points
3. [Guide/03-Basic-Exploitation.md](Guide/03-Basic-Exploitation.md) - Extract data via errors and boolean logic

### Goal 2: Efficient Data Extraction

For penetration testers who need to extract data quickly:

4. [Guide/04-Union-Injection.md](Guide/04-Union-Injection.md) - Fast extraction with UNION
5. [Guide/05-Database-Fingerprinting.md](Guide/05-Database-Fingerprinting.md) - Identify your target
6. [Guide/06-Schema-Enumeration.md](Guide/06-Schema-Enumeration.md) - Map the database structure
7. [Guide/07-Data-Extraction.md](Guide/07-Data-Extraction.md) - Dump data efficiently

### Goal 3: Bypassing Defenses

For advanced scenarios with WAFs or input filters:

8. [Guide/08-Blind-Injection.md](Guide/08-Blind-Injection.md) - When no output is visible
9. [Guide/09-Filter-Evasion.md](Guide/09-Filter-Evasion.md) - Bypass WAFs and filters
10. [Guide/10-Advanced-Techniques.md](Guide/10-Advanced-Techniques.md) - Stacked queries and file operations

### Goal 4: Full System Compromise

For red team operations and advanced exploitation:

11. [Guide/10-Advanced-Techniques.md](Guide/10-Advanced-Techniques.md) - File system access
12. [Guide/11-OS-Command-Execution.md](Guide/11-OS-Command-Execution.md) - Achieve command execution

### Goal 5: Advanced Contexts & Modern APIs

For specialized scenarios and modern application architectures:

13. [Guide/12-Second-Order-Injection.md](Guide/12-Second-Order-Injection.md) - Stored/delayed injection attacks
14. [Guide/13-Alternative-Context-Injection.md](Guide/13-Alternative-Context-Injection.md) - JSON, XML, HTTP header, and cookie injection
15. [Guide/14-HTTP-Parameter-Pollution.md](Guide/14-HTTP-Parameter-Pollution.md) - HPP attacks and framework bypass
16. [Guide/15-Heavy-Query-DoS.md](Guide/15-Heavy-Query-DoS.md) - Resource exhaustion and DoS via SQL

### Goal 6: Specialized Injection Vectors

For niche attack surfaces and bypass techniques:

17. [Guide/16-JWT-SQL-Injection.md](Guide/16-JWT-SQL-Injection.md) - JWT KID parameter injection
18. [Guide/17-GraphQL-SQL-Injection.md](Guide/17-GraphQL-SQL-Injection.md) - GraphQL resolver injection
19. [Guide/18-ORM-Injection.md](Guide/18-ORM-Injection.md) - ORM framework bypass techniques
20. [Guide/19-Polyglot-Payloads.md](Guide/19-Polyglot-Payloads.md) - Multi-context polyglot payloads
21. [Guide/20-Multibyte-Encoding-Bypass.md](Guide/20-Multibyte-Encoding-Bypass.md) - Character set encoding bypasses
22. [Guide/21-NoSQL-Injection.md](Guide/21-NoSQL-Injection.md) - MongoDB, Redis, Cassandra, Elasticsearch injection

## Prerequisites

- Basic SQL knowledge (SELECT, WHERE, JOIN)
- Understanding of HTTP requests and responses
- Familiarity with command line tools

## Practice Labs

```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
# Login: admin / password
# Set security level to "low" or "medium"
```

## How to Use This Guide

1. **Follow the order**: Each chapter builds on previous knowledge
2. **Practice immediately**: Set up a lab and test every payload
3. **Take notes**: Document what works and what does not
4. **Use the cheat sheet**: Keep [Guide/22-Cheat-Sheet.md](Guide/22-Cheat-Sheet.md) open while testing
5. **Be ethical**: Only test on systems you own or have explicit permission to test

## Legal Notice

**IMPORTANT**: This material is for **authorized security testing and educational purposes only**.

- Never test on systems without **explicit written permission**
- Unauthorized access to computer systems is illegal in most jurisdictions
- Always follow responsible disclosure practices
- Use isolated lab environments for learning

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for details.
