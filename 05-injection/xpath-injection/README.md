# XPath Injection

> **OWASP Top 10:2025**: A05:2025 – Injection | **CWE**: CWE-643 | **Nguồn**: PortSwigger, OWASP, CWE MITRE

## 🧱 Kiến thức Nền tảng

**XPath** (XML Path Language) là ngôn ngữ truy vấn dùng để chọn các node trong tài liệu XML — tương tự như SQL dùng cho cơ sở dữ liệu quan hệ. Nhiều ứng dụng sử dụng XML để lưu trữ cấu hình, dữ liệu người dùng, hoặc làm trung gian trao đổi dữ liệu giữa các hệ thống.

Cú pháp XPath cho phép duyệt cây XML bằng các biểu thức đường dẫn (path expression). Ví dụ, `//user[name='admin']` sẽ tìm tất cả node `<user>` có child node `<name>` bằng `admin`.

Một cấu trúc XML lưu trữ thông tin người dùng điển hình:

```xml
<!-- users.xml — XML-based user database -->
<users>
  <user>
    <name>admin</name>
    <password>s3cur3P@ss</password>
    <role>administrator</role>
  </user>
  <user>
    <name>guest</name>
    <password>guest123</password>
    <role>viewer</role>
  </user>
</users>
```

Ứng dụng xác thực người dùng bằng XPath query:

```python
# Normal authentication using XPath query
import lxml.etree as ET

tree = ET.parse('users.xml')

# Build XPath to find matching user
query = f"//user[name='{username}' and password='{password}']"
result = tree.xpath(query)

if result:
    print("Login successful")
```

## 🔍 Mô tả lỗ hổng

XPath Injection xảy ra khi ứng dụng xây dựng XPath query bằng cách nối chuỗi (string concatenation) với dữ liệu từ người dùng mà không sanitize. Khác với SQL Injection, XPath Injection có một số đặc điểm riêng:

- **Không có hệ thống phân quyền**: XPath truy cập toàn bộ tài liệu XML — không có khái niệm "user permission" như trong database.
- **Toàn bộ dữ liệu nằm trong một file**: Một khi khai thác thành công, attacker có thể trích xuất mọi thông tin trong XML.
- **Không có comment hoặc statement stacking**: Nhưng vẫn có thể sử dụng toán tử logic `or`, `and` để bypass điều kiện.

## ⚔️ Cơ chế tấn công

**Authentication Bypass** — Classic tautology attack tương tự SQL Injection:

```
# Malicious input
username: ' or '1'='1
password: ' or '1'='1

# Resulting XPath query becomes:
//user[name='' or '1'='1' and password='' or '1'='1']
# This always evaluates to TRUE — returns all users
```

**Data Extraction bằng Boolean-based Blind XPath Injection**:

```
# Extract the first character of the first user's password
' or substring(//user[1]/password, 1, 1)='s' or 'a'='b

# If response differs when char matches, attacker can brute-force each character
# Iterate: position 1→N, testing chars a-z, 0-9, symbols
```

**Trích xuất tên node bằng hàm name()**:

```
# Discover node names in the XML structure
' or name(//user[1]/child::*[1])='name' or '1'='2

# Attacker can enumerate the entire XML schema
```

## 🛡️ Biện pháp phòng thủ

1. **Parameterized XPath queries**: Sử dụng XPath variable binding thay vì nối chuỗi — tương tự prepared statement trong SQL.
2. **Input validation**: Whitelist ký tự cho phép (alphanumeric), reject ký tự đặc biệt `'`, `"`, `/`, `[`, `]`.
3. **Chuyển sang cơ sở dữ liệu**: Nếu dữ liệu quan trọng, migrate từ XML file sang database có hệ thống phân quyền.
4. **Least privilege**: Giới hạn scope XPath query chỉ truy vấn node cần thiết.
5. **Error handling**: Không expose XPath error message ra cho client.

## 💻 Code Example

```python
# === VULNERABLE CODE ===
from lxml import etree

def login_vulnerable(username, password):
    tree = etree.parse('users.xml')
    # DANGER: String concatenation with user input
    query = f"//user[name='{username}' and password='{password}']"
    result = tree.xpath(query)
    return len(result) > 0


# === SECURE CODE ===
from lxml import etree
import re

def login_secure(username, password):
    tree = etree.parse('users.xml')

    # Validate input — allow only alphanumeric characters
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False
    if not re.match(r'^[a-zA-Z0-9@!#_]+$', password):
        return False

    # Use XPath variables for parameterized queries
    # lxml supports XPath variables via the 'variables' parameter
    query = "//user[name=$uname and password=$pwd]"
    result = tree.xpath(query, uname=username, pwd=password)
    return len(result) > 0
```

## 📚 Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/xpath-injection
- OWASP: https://owasp.org/www-community/attacks/XPATH_Injection
- CWE: https://cwe.mitre.org/data/definitions/643.html
