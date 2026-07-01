# XML Bombs

> **CWE**: CWE-776 (Improper Neutralization of Recursive Entity References in DTDs), CWE-400 (Uncontrolled Resource Consumption) | **Phân loại**: XML Attacks

## Kiến thức Nền tảng
Hãy tưởng tượng bạn nhận được một hộp quà nhỏ từ bưu điện. Khi mở hộp ra, bạn thấy bên trong có 10 chiếc hộp nhỏ hơn. Mở mỗi chiếc hộp nhỏ đó, bạn lại thấy 10 chiếc hộp nhỏ hơn nữa. Quá trình này lặp lại liên tục. Ban đầu chiếc hộp trông rất gọn nhẹ, nhưng khi bạn cố mở hết ra, đống hộp khổng lồ sẽ tràn ngập khắp căn phòng của bạn, không còn chỗ để thở.
Trong ngôn ngữ XML, cơ chế này tương đương với **Lồng thực thể (XML Entity Nesting)**. XML cho phép lập trình viên tạo ra các "phím tắt" (gọi là thực thể - entities) thông qua định nghĩa DTD để viết code nhanh hơn. Một phím tắt này có thể gọi đến các phím tắt khác lồng nhau.

Khi hệ thống dịch mã XML (XML Parser) đọc tệp tin này, nó sẽ thực hiện nhiệm vụ dịch nghĩa các phím tắt đó ra nội dung thực tế (quá trình **Entity Expansion** - mở rộng thực thể).
Nếu trình phân dịch này quá ngây thơ và không có giới hạn an toàn, cấu trúc lồng nhau dạng lũy thừa (chỉ cần lồng nhau 9 cấp, mỗi cấp nhân bản 10 lần) sẽ tạo ra một hiệu ứng dây chuyền kinh hoàng: 1 từ viết tắt ban đầu sẽ phình to thành 1 tỷ từ thô trong bộ nhớ!
Chiếc tệp XML siêu nhỏ ban đầu chỉ nặng khoảng vài Kilobytes bỗng chốc biến thành một "quả bom tấn" phình to lên hàng trăm Megabytes hoặc hàng Gigabytes dữ liệu trong RAM. Máy chủ xử lý không kịp, cạn kiệt bộ nhớ (Out of Memory) và sụp đổ ngay lập tức.

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

## Mô tả lỗ hổng
Lỗ hổng **XML Bomb (còn được gọi là Billion Laughs - Quả bom một tỷ tiếng cười)** là một chiếc bẫy tinh vi nhắm vào bộ nhớ của máy chủ. Nó xảy ra do các thư viện phân tích cú pháp XML cũ mặc định cho phép người dùng tự định nghĩa các từ viết tắt đệ quy.

Kẻ tấn công chỉ cần gửi một đoạn dữ liệu XML cực nhỏ nhưng chứa cấu trúc lồng nhau đệ quy.
Sự nguy hiểm của lỗ hổng này nằm ở chỗ:
- Máy chủ không thể nhận biết tệp tin này nguy hiểm chỉ qua dung lượng tải lên (vì tệp tin thực tế cực kỳ nhẹ, dễ dàng vượt qua các bộ lọc kích thước file).
- Chỉ khi máy chủ bắt đầu phân tích cú pháp (parse) và giải nén các thực thể lồng nhau, "quả bom" mới bắt đầu phát nổ. Nó vắt kiệt từng byte RAM và chiếm dụng 100% CPU để xử lý chuỗi ký tự khổng lồ, khiến toàn bộ máy chủ bị treo và ngừng phục vụ tất cả người dùng khác (DoS).

## Cơ chế tấn công
Kẻ tấn công gửi một tệp XML chứa các định nghĩa thực thể lồng nhau (ví dụ: định nghĩa thực thể `lol1` chứa 10 thực thể `lol`, thực thể `lol2` chứa 10 thực thể `lol1`, cứ như thế lặp lại 9 cấp đến `lol9`). Khi parser phân tích cú pháp và cố gắng mở rộng thực thể `lol9` này ra văn bản thô, 1 thực thể ban đầu sẽ nhân bản thành 1 tỷ thực thể `lol`. Điều này khiến kích thước tệp ban đầu chỉ khoảng 1 KB phình to thành hàng trăm megabytes dữ liệu trong bộ nhớ RAM của máy chủ, vắt kiệt tài nguyên xử lý và làm sập ứng dụng.

## Biện pháp phòng thủ
- **Tóm tắt**: Phòng chống XML Bomb bằng cách vô hiệu hóa hoàn toàn DTD nội tuyến hoặc giới hạn số lượng mở rộng thực thể tối đa trong cấu hình parser XML.
- **Các bước chi tiết**:
  - Vô hiệu hóa hoàn toàn việc xử lý DTD nội tuyến (Document Type Definitions) trong bộ phân tích cú pháp XML.
  - Vô hiệu hóa tính năng phân giải thực thể XML bên ngoài (XXE).
  - Nếu DTD là bắt buộc đối với nghiệp vụ, hãy thiết lập giới hạn chặt chẽ về số lượng thực thể tối đa được phép mở rộng, kích thước tối đa của thuộc tính và kích thước tổng thể của tệp đầu vào.
  - Chuyển sang sử dụng các định dạng dữ liệu an toàn hơn như JSON thay thế cho XML khi có thể.

## Code Example
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

```python
# VULNERABLE: parsing XML without entity expansion limit
import xml.etree.ElementTree as ET  # stdlib is NOT safe for untrusted XML

def parse_xml_vulnerable(xml_string):
    # ElementTree does NOT protect against entity expansion attacks
    tree = ET.fromstring(xml_string)  # Billion Laughs will consume all RAM
    return tree

# SAFE: use defusedxml which blocks entity expansion
import defusedxml.ElementTree as SafeET

def parse_xml_safe(xml_string):
    # defusedxml raises DefusedXmlException on XML bomb attempt
    tree = SafeET.fromstring(xml_string)
    return tree
```

## Xem thêm
- [XML External Entities](../../05-injection/xxe/) — Lỗ hổng chèn thực thể XML bên ngoài cho phép đọc file hệ thống hoặc thực hiện SSRF thay vì gây cạn kiệt tài nguyên máy chủ.

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP XML Cheat Sheet, CWE-776, CWE-400

## Giải thích thuật ngữ
- **XML Entity (Thực thể XML)**: Hoạt động như một biến hoặc một lối tắt thay thế cho đoạn văn bản dài hơn trong tài liệu XML.
- **DTD (Document Type Definition)**: Định nghĩa kiểu tài liệu, dùng để quy định cấu trúc ngữ pháp và các thực thể hợp lệ được sử dụng trong tệp XML.
- **XML Parser**: Bộ phân tích cú pháp XML, chịu trách nhiệm đọc và biên dịch tệp XML thành cấu trúc dữ liệu mà ứng dụng hiểu được.
- **Entity Expansion (Mở rộng thực thể)**: Quá trình thay thế các thực thể viết tắt bằng giá trị văn bản thực tế của chúng trong khi xử lý XML.
- **Out of Memory (OOM)**: Lỗi cạn kiệt bộ nhớ RAM của hệ thống, khiến ứng dụng hoặc máy chủ bị tắt đột ngột do không thể cấp phát thêm bộ nhớ.
- **Billion Laughs (Một tỷ tiếng cười)**: Tên gọi phổ biến của cuộc tấn công XML Bomb, xuất phát từ việc lặp lại đệ quy thực thể mang giá trị "lol" (viết tắt của cười lớn) lên đến một tỷ lần.
- **Defusedxml**: Thư viện Python an toàn dùng để thay thế bộ parser XML mặc định, tự động chặn đứng các cuộc tấn công XML Bomb và chèn thực thể bên ngoài.
