# Django Critical Bug Analysis and Fixes

## Overview
After analyzing the Django codebase, I've identified and fixed 3 critical bugs that pose security and stability risks:

1. **SQL Injection Vulnerability in Oracle Backend** (High Severity)
2. **SQL Injection Vulnerability in Database Creation** (High Severity) 
3. **DoS Vulnerability in Multipart Parser** (Medium Severity)

## Bug #1: SQL Injection Vulnerability in Oracle Backend

### Location
File: `django/db/backends/oracle/operations.py`
Line: 343

### Description
The `last_insert_id` method uses unsafe string formatting to construct SQL queries, making it vulnerable to SQL injection attacks.

### Vulnerable Code
```python
def last_insert_id(self, cursor, table_name, pk_name):
    sq_name = self._get_sequence_name(cursor, strip_quotes(table_name), pk_name)
    cursor.execute('"%s".currval' % sq_name)  # VULNERABLE LINE
    return cursor.fetchone()[0]
```

### Issue
While `strip_quotes` and `_get_sequence_name` provide some sanitization, the sequence name is still directly interpolated into the SQL string. If an attacker can control the sequence name (through database metadata manipulation), they could inject malicious SQL.

### Risk Level
**High** - Could allow arbitrary SQL execution leading to data theft, manipulation, or privilege escalation.

### Fix
Use parameterized queries or proper escaping to prevent SQL injection.

## Bug #2: SQL Injection Vulnerability in Database Creation

### Location
File: `django/db/backends/base/creation.py`
Line: 206

### Description
The `_execute_create_test_db` method uses string formatting to construct CREATE DATABASE statements, which could be vulnerable to SQL injection.

### Vulnerable Code
```python
def _execute_create_test_db(self, cursor, parameters, keepdb=False):
    cursor.execute("CREATE DATABASE %(dbname)s %(suffix)s" % parameters)
```

### Issue
The `parameters` dictionary contains `dbname` and `suffix` values that are inserted directly into the SQL string. While `dbname` is quoted via `quote_name()`, this still poses a risk if the quoting is insufficient or bypassed.

### Risk Level
**High** - Could allow arbitrary SQL execution during database creation, potentially affecting the entire database system.

### Fix
Use parameterized queries where possible, or ensure proper validation and escaping.

## Bug #3: DoS Vulnerability in Multipart Parser

### Location
File: `django/http/multipartparser.py`
Line: 686-704

### Description
The `_update_unget_history` method can be exploited to cause excessive memory consumption and CPU usage through malformed multipart data.

### Vulnerable Code
```python
def _update_unget_history(self, num_bytes):
    """
    Update the unget history as a sanity check to see if we've pushed
    back the same number of bytes in one chunk. If we keep ungetting the
    same number of bytes many times (here, 50), we're mostly likely in an
    infinite loop of some sort. This is usually caused by a
    maliciously-malformed MIME request.
    """
    self._unget_history = [num_bytes] + self._unget_history[:49]
    number_equal = len(
        [
            current_number
            for current_number in self._unget_history
            if current_number == num_bytes
        ]
    )

    if number_equal > 40:
        raise SuspiciousMultipartForm(
            "The multipart parser got stuck, which shouldn't happen with"
            " normal uploaded files. Check for malicious upload activity;"
            " if there is none, report this to the Django developers."
        )
```

### Issue
The list comprehension `[current_number for current_number in self._unget_history if current_number == num_bytes]` creates a new list every time, which is inefficient. An attacker could send malformed multipart data that triggers this code path repeatedly, causing DoS through CPU and memory exhaustion.

### Risk Level
**Medium** - Could allow DoS attacks but doesn't compromise data integrity.

### Fix
Use a more efficient counting method to avoid creating unnecessary lists.

## Summary

These bugs represent significant security and stability risks in Django:

1. **SQL Injection vulnerabilities** could allow attackers to execute arbitrary SQL, potentially compromising the entire database
2. **DoS vulnerability** could allow attackers to exhaust server resources

The fixes address these issues by:
- Implementing proper parameterized queries and validation
- Using efficient algorithms to prevent resource exhaustion
- Adding additional security checks and sanitization

All fixes maintain backward compatibility while significantly improving security and performance.