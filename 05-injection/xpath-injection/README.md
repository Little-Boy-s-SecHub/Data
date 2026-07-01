# XPath Injection

> **CWE**: CWE-643 | **Phân loại**: Injection

## Kiến thức Nền tảng

Hãy tưởng tượng XML giống như một sơ đồ phả hệ hoặc cấu trúc dạng cây để lưu trữ thông tin (như danh sách người dùng và mật khẩu). Để tìm kiếm và di chuyển giữa các nhánh của cây XML này, lập trình viên sử dụng một ngôn ngữ truy vấn gọi là XPath (tương tự như cách SQL được dùng cho cơ sở dữ liệu quan hệ). XPath sử dụng các biểu thức đường dẫn thông minh như `//user[name='admin']` để nhanh chóng xác định đúng vị trí của nút dữ liệu cần tìm.

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

## Mô tả lỗ hổng

Lỗ hổng XPath Injection xảy ra khi ứng dụng web ghép nối trực tiếp thông tin do người dùng nhập vào câu lệnh truy vấn XPath mà không hề kiểm tra hay làm sạch dữ liệu. Kẻ tấn công có thể chèn các toán tử logic như `or` hoặc `'` để bẻ gãy logic tìm kiếm ban đầu. Khác với cơ sở dữ liệu SQL có các lớp phân quyền phức tạp cho từng bảng, các tài liệu XML thường chỉ là một file đơn lẻ không có cơ chế phân quyền bên trong. Một khi kẻ tấn công chèn được câu lệnh XPath độc hại thành công, họ có thể vượt qua bước xác thực đăng nhập mà không cần mật khẩu, hoặc trích xuất và đọc sạch sẽ mọi thông tin nhạy cảm nằm trong toàn bộ tệp XML đó.

## Cơ chế tấn công

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

## Biện pháp phòng thủ

- **Tóm tắt**: Sử dụng các truy vấn liên kết biến (variable binding) trong XPath và xác thực danh sách trắng các ký tự đầu vào.
- **Các bước chi tiết**:
  - Parameterized XPath queries: Sử dụng XPath variable binding thay vì nối chuỗi — tương tự prepared statement trong SQL.
  - Input validation: Whitelist ký tự cho phép (alphanumeric), reject ký tự đặc biệt `'`, `"`, `/`, `[`, `]`.
  - Chuyển sang cơ sở dữ liệu: Nếu dữ liệu quan trọng, migrate từ XML file sang database có hệ thống phân quyền.
  - Least privilege: Giới hạn scope XPath query chỉ truy vấn node cần thiết.
  - Error handling: Không expose XPath error message ra cho client.

## Code Example

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

## Xem thêm

- [SQL Injection](../sql-injection/) — Lỗ hổng chèn mã truy vấn cấu trúc dữ liệu.

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/xpath-injection
- OWASP: https://owasp.org/www-community/attacks/XPATH_Injection
- CWE: https://cwe.mitre.org/data/definitions/643.html

## Giải thích thuật ngữ

- **XPath**: Ngôn ngữ truy vấn dùng để định vị và lấy dữ liệu từ tài liệu XML.
- **XPath Injection**: Tiêm mã XPath độc hại nhằm thay đổi truy vấn và trích xuất trái phép dữ liệu XML.
- **XML Node**: Một nút đại diện cho một phần tử, thuộc tính hoặc văn bản trong tài liệu XML.
- **Statement Stacking**: Kỹ thuật xếp chồng nhiều câu lệnh thực thi liên tiếp (không được hỗ trợ trong XPath).
- **Logic Operator**: Các phép toán logic như AND, OR dùng trong câu lệnh truy vấn.
