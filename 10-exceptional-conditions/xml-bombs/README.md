# XML Bombs

> **OWASP Top 10:2025**: A10:2025 – Mishandling of Exceptional Conditions | **CWE**: CWE-776 (Improper Neutralization of Recursive Entity References in DTDs), CWE-400 (Uncontrolled Resource Consumption) | **Phân loại**: System

## 🧱 Kiến thức Nền tảng
Tấn công XML Bomb (hay còn gọi là Billion Laughs) là một hình thức tấn công Từ chối Dịch vụ (DoS) nhắm vào các bộ phân tích cú pháp (parsers) của ứng dụng XML. Để hiểu được lý do một tệp tin XML cực nhỏ có thể đánh sập một hệ thống máy chủ, chúng ta cần tìm hiểu cơ chế xử lý thực thể sau:

1. **XML entity nesting (Lồng thực thể XML)**: Ngôn ngữ XML cho phép định nghĩa các thực thể (entities) thông qua DTD (Document Type Definition) làm phím tắt để thay thế văn bản khi xử lý. Các thực thể này không chỉ chứa chuỗi ký tự tĩnh mà còn có thể tham chiếu lồng nhau (nesting). Ví dụ, thực thể `&lol2;` được cấu thành từ nhiều thực thể `&lol1;`, và đến lượt mình, `&lol1;` lại tham chiếu đến các thực thể `&lol;` cơ bản. Cấu trúc lồng ghép này tạo thành một mô hình phân cấp giống như một cây thực thể.
2. **Entity expansion (Mở rộng thực thể)**: Khi parser xử lý tài liệu XML, nó sẽ giải quyết đệ quy các thực thể này bằng cách thay thế các tham chiếu thực thể bằng nội dung thực của chúng (quá trình expansion). Nếu parser không được giới hạn, cấu trúc lồng nhau dạng lũy thừa (ví dụ lồng nhau 9 cấp, mỗi cấp nhân bản 10 lần) sẽ khiến 1 thực thể gốc phình to thành $10^9$ (1 tỷ) thực thể thô. Quá trình giải nén này tiêu tốn dung lượng bộ nhớ khổng lồ trên RAM (từ vài Kilobytes ban đầu phình to thành hàng trăm Megabytes hoặc thậm chí Gigabytes) và chiếm trọn tài nguyên CPU, khiến máy chủ hết bộ nhớ (Out of Memory) và dừng hoạt động ngay lập tức.

### Minh họa hoạt động bình thường (Normal Operation)
```python
# Normal operation: Safe XML parsing with entities disabled using defusedxml
import defusedxml.ElementTree as ET

# Normal XML data representing a simple user profile without recursive entities
normal_xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<profile>
    <name>Jane Doe</name>
    <email>jane.doe@example.com</email>
    <role>Developer</role>
</profile>
"""

def parse_user_profile(xml_string):
    try:
        # Securely parse the XML string
        # defusedxml automatically blocks dynamic entity expansion and DTD declaration injection
        root = ET.fromstring(xml_string)
        
        # Extract text content safely from the validated nodes
        name = root.find('name').text
        email = root.find('email').text
        role = root.find('role').text
        
        print(f"Profile Loaded - Name: {name}, Email: {email}, Role: {role}")
        return {"name": name, "email": email, "role": role}
    except ET.ParseError as e:
        print(f"XML Parsing failed due to syntax or security restriction: {e}")
        return None

# Parse standard, non-malicious XML data
parse_user_profile(normal_xml_data)
```

## 🔍 Mô tả lỗ hổng
XML Bomb (hay còn gọi là cuộc tấn công Billion Laughs) khai thác các thư viện phân tích cú pháp XML cho phép khai báo DTD nội tuyến và mở rộng thực thể (entity expansion) đệ quy. Kẻ tấn công có thể thiết kế một tài liệu XML nhỏ nhưng chứa các thực thể lồng nhau, khiến tài liệu phình to gấp hàng triệu lần khi phân tích. Lỗ hổng này dẫn đến cạn kiệt CPU, RAM của máy chủ và gây ra từ chối dịch vụ (Denial of Service).

## ⚔️ Cơ chế tấn công
Kẻ tấn công gửi một tệp XML chứa các định nghĩa thực thể lồng nhau (ví dụ: định nghĩa thực thể `lol1` chứa 10 thực thể `lol`, thực thể `lol2` chứa 10 thực thể `lol1`, cứ như thế lặp lại 9 cấp đến `lol9`). Khi parser phân tích cú pháp và cố gắng mở rộng thực thể `lol9` này ra văn bản thô, 1 thực thể ban đầu sẽ nhân bản thành 1 tỷ thực thể `lol`. Điều này khiến kích thước tệp ban đầu chỉ khoảng 1 KB phình to thành hàng trăm megabytes dữ liệu trong bộ nhớ RAM của máy chủ, vắt kiệt tài nguyên xử lý và làm sập ứng dụng.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Phòng chống XML Bomb bằng cách vô hiệu hóa hoàn toàn DTD nội tuyến hoặc giới hạn số lượng mở rộng thực thể tối đa trong cấu hình parser XML.
- **Các bước chi tiết**:
  - Vô hiệu hóa hoàn toàn việc xử lý DTD nội tuyến (Document Type Definitions) trong bộ phân tích cú pháp XML.
  - Vô hiệu hóa tính năng phân giải thực thể XML bên ngoài (XXE).
  - Nếu DTD là bắt buộc đối với nghiệp vụ, hãy thiết lập giới hạn chặt chẽ về số lượng thực thể tối đa được phép mở rộng, kích thước tối đa của thuộc tính và kích thước tổng thể của tệp đầu vào.
  - Chuyển sang sử dụng các định dạng dữ liệu an toàn hơn như JSON thay thế cho XML khi có thể.

## 💻 Code Example
```python
# Secure XML parsing in Python using 'defusedxml' library
import defusedxml.ElementTree as ET

xml_data = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>"""

try:
    # defusedxml blocks entity expansion and external entities automatically
    root = ET.fromstring(xml_data)
except Exception as e:
    print(f"Safe parser blocked XML bomb: {e}")
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã sửa đổi sự không nhất quán giữa mô tả trong slide và thực tế kỹ thuật: văn bản Slide 13 ghi kích thước payload mở rộng đạt "3 gigabytes", trong khi cấu hình định nghĩa ở Slide 8 lồng nhau 9 cấp (`lol9`) thực tế chỉ phình ra tối đa khoảng "300 megabytes". Nội dung văn bản mô tả đã được cập nhật thành "300 megabytes" cho chính xác.
- **Nguồn tham khảo**: OWASP XML Cheat Sheet, CWE-776, CWE-400
