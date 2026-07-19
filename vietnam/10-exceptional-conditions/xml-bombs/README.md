---
schema_version: 1
id: WEB-A10-XML-BOMBS
title: "XML Bombs"
slug: xml-bombs
level: advanced
estimated_minutes: 65
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A02:2025
cwe:
  - CWE-776
  - CWE-400
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# XML Bombs

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích XML Bombs bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống XML Bombs và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn nhận được một hộp quà nhỏ từ bưu điện. Khi mở hộp ra, bạn thấy bên trong có 10 chiếc hộp nhỏ hơn. Mở mỗi chiếc hộp nhỏ đó, bạn lại thấy 10 chiếc hộp nhỏ hơn nữa. Quá trình này lặp lại liên tục. Ban đầu chiếc hộp trông rất gọn nhẹ, nhưng khi bạn cố mở hết ra, đống hộp khổng lồ sẽ tràn ngập khắp căn phòng của bạn, không còn chỗ để thở.
Trong ngôn ngữ XML, cơ chế này tương đương với **Lồng thực thể (XML Entity Nesting)**. XML cho phép lập trình viên tạo ra các "phím tắt" (gọi là thực thể - entities) thông qua định nghĩa DTD để viết code nhanh hơn. Một phím tắt này có thể gọi đến các phím tắt khác lồng nhau.

Khi hệ thống dịch mã XML (XML Parser) đọc tệp tin này, nó sẽ thực hiện nhiệm vụ dịch nghĩa các phím tắt đó ra nội dung thực tế (quá trình **Entity Expansion** - mở rộng thực thể).
Nếu parser không có giới hạn an toàn, cấu trúc lồng nhau dạng lũy thừa (9 cấp, mỗi cấp tham chiếu thực thể trước 10 lần) có thể tạo ra tới một tỷ lần thay thế của thực thể gốc.
Chiếc tệp XML siêu nhỏ ban đầu chỉ nặng khoảng vài Kilobytes bỗng chốc biến thành một "quả bom tấn" phình to lên hàng trăm Megabytes hoặc hàng Gigabytes dữ liệu trong RAM. Máy chủ xử lý không kịp, cạn kiệt bộ nhớ (Out of Memory) và sụp đổ ngay lập tức.

### Minh họa hoạt động bình thường (Normal Operation)
```python
# Normal operation: Safe XML parsing with entities disabled using defusedxml
import defusedxml.ElementTree as ET

# Normal XML data representing a simple user profile without recursive entities
normal_xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<profile>
    <name>Jane Doe</name>
    <email>jane.doe@victim.lab.test</email>
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

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **XML Bomb (thường gặp qua Billion Laughs hoặc Quadratic Blowup)** là một chiếc bẫy tinh vi nhắm vào bộ nhớ của máy chủ. Nó xảy ra do các thư viện phân tích cú pháp XML cũ mặc định cho phép người dùng tự định nghĩa thực thể nội bộ rồi mở rộng chúng quá mức.

Kẻ tấn công chỉ cần gửi một đoạn dữ liệu XML cực nhỏ nhưng chứa cấu trúc lồng nhau đệ quy.
Sự nguy hiểm của lỗ hổng này nằm ở chỗ:
- Máy chủ không thể nhận biết tệp tin này nguy hiểm chỉ qua dung lượng tải lên (vì tệp tin thực tế cực kỳ nhẹ, dễ dàng vượt qua các bộ lọc kích thước file).
- Chỉ khi parser mở rộng các thực thể lồng nhau, mức sử dụng CPU/bộ nhớ mới tăng mạnh; kết quả cụ thể phụ thuộc parser, phiên bản và giới hạn tài nguyên. Expat 2.4.1 trở lên có bảo vệ cho Billion Laughs, nhưng bản Python liên kết với thư viện hệ thống có thể khác nên phải kiểm tra `pyexpat.EXPAT_VERSION`. [S4]

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** CPU, memory, thời gian xử lý và worker của XML parser/service.
- **Trust boundary:** XML body do client gửi đi vào parser với cấu hình DTD/general entity và giới hạn expansion cụ thể.
- **Actor:** client local chưa đăng nhập hoặc user fixture, chỉ gửi tài liệu XML giảm độ sâu trong container giới hạn tài nguyên.
- **Điều kiện cần:** parser cho phép entity expansion và thiếu/không đủ giới hạn về body, số entity, độ sâu hoặc thời gian xử lý.
- **Điều kiện môi trường:** Python 3.12; ghi lại `pyexpat.EXPAT_VERSION` hoặc phiên bản libxml thực tế; container không outbound và có CPU/memory timeout.

Billion Laughs dùng entity nội bộ nên chặn outbound không ngăn được nó; bản sửa phải tắt DTD/entity khi không cần hoặc áp giới hạn parser có thể kiểm chứng. [S1]

## 6. Cơ chế tấn công

General entity tham chiếu lồng nhau có thể làm output tăng nhanh hơn input, khiến parser tiêu thụ CPU/memory trước khi ứng dụng xử lý DOM. Kiểm thử dùng biến thể giảm độ sâu, so peak resource/elapsed time với XML bình thường và xác nhận cấu hình an toàn từ chối trước expansion. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy parser fixture trong container capped; ghi Python/parser version, cấu hình DTD/entity và baseline resource metrics.
2. **Input:** dùng XML nhỏ hợp lệ, XML có DTD bị cấm và bomb giảm độ sâu với kích thước/expansion tối đa được định trước.
3. **Thao tác:** tăng một cấp entity mỗi lượt; ghi elapsed time, peak RSS, exit/status và parser exception.
4. **Expected result:** cấu hình dễ lỗi cho thấy expansion tăng rõ; cấu hình an toàn từ chối DTD/entity hoặc dừng tại hard limit mà worker vẫn khả dụng.
5. **Cleanup:** dừng fixture, xóa XML/log tạm và xác nhận container không còn process.
6. **Giới hạn an toàn:** không chạy full Billion Laughs; dừng trước resource cap, không dùng external entity hay callback Internet.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

Lesson chỉ giữ seed giảm cấp có giới hạn để kiểm tra policy mà không gây cạn kiệt tài nguyên. Payload đầy đủ kiểu Billion Laughs hoặc Quadratic Blowup không được phát hành trong bài.

<!-- payload-id: WEB-A10-XML-BOMBS-001 -->
<!-- context: XML 1.0 với internal DTD; parser fixture phải ghi rõ implementation và phiên bản Expat/libxml -->
<!-- prerequisites: container local có timeout, memory/CPU cap và không có outbound network -->
<!-- encoding: UTF-8; document hoàn chỉnh, không nén -->
<!-- expected-result: parser hardened từ chối DTD/entity expansion; fixture quan sát mở rộng tối đa 100 chuỗi lol rồi dừng, không tăng cấp -->
<!-- risk: dos -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2,S4 -->
<!-- last-verified: 2026-07-17 -->
```xml
<?xml version="1.0"?>
<!DOCTYPE probe [
  <!ENTITY e0 "lol">
  <!ENTITY e1 "&e0;&e0;&e0;&e0;&e0;&e0;&e0;&e0;&e0;&e0;">
  <!ENTITY e2 "&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;">
]>
<probe>&e2;</probe>
```

**Quadratic Blowup giảm cấp**

<!-- payload-id: WEB-A10-XML-BOMBS-002 -->
<!-- context: XML 1.0 internal DTD; parser fixture must record implementation and expansion limits -->
<!-- prerequisites: container local has timeout and memory/CPU cap; entity value is intentionally small and repeated count is bounded -->
<!-- encoding: UTF-8; document complete and uncompressed -->
<!-- expected-result: hardened parser rejects DTD/entity expansion; vulnerable fixture records repeated expansion cost without exceeding lab cap -->
<!-- risk: dos -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S4 -->
<!-- last-verified: 2026-07-18 -->
```xml
<?xml version="1.0"?>
<!DOCTYPE probe [
  <!ENTITY block "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">
]>
<probe>&block;&block;&block;&block;&block;&block;&block;&block;</probe>
```

## 9. Code dễ bị lỗi và code an toàn

Hai hàm sau dùng Python 3.12 và `defusedxml` 0.7.1 cho cùng use case parse tài liệu XML nhỏ. Bản dễ lỗi tắt các cờ bảo vệ và không giới hạn input; bản an toàn giới hạn bytes trước parse rồi cấm DTD, entity và external reference. Vẫn cần timeout/memory cap ở tầng service cho defense-in-depth. [S4] [S5]

### Không an toàn (vulnerable): tắt bảo vệ của parser

```python
from defusedxml import ElementTree as DefusedET

def parse_xml_vulnerable(xml_text):
    # Vulnerable: all defusedxml protections are explicitly disabled
    return DefusedET.fromstring(
        xml_text,
        forbid_dtd=False,
        forbid_entities=False,
        forbid_external=False,
    )
```

### An toàn (secure): giới hạn input và cấm cấu trúc không cần thiết

```python
from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException
from xml.etree.ElementTree import ParseError

MAX_XML_BYTES = 64 * 1024

def parse_xml_secure(xml_text):
    raw = xml_text.encode('utf-8')
    if len(raw) > MAX_XML_BYTES:
        raise ValueError('XML document exceeds the configured byte limit')
    try:
        return DefusedET.fromstring(
            xml_text,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except (DefusedXmlException, ParseError) as exc:
        raise ValueError("Rejected unsafe XML") from exc
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến XML Bombs, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Giới hạn tài nguyên, fail safely và xử lý mọi trạng thái ngoại lệ có thể đạt tới.
- Tắt DTD/general entity khi không cần; pin parser đã vá và đặt hard limit cho body, expansion, depth, CPU/memory và thời gian xử lý.
- Dùng cùng một policy cho mọi route/operation tương đương; không chỉ sửa endpoint xuất hiện trong PoC.

### Defense-in-depth

Với XML Bombs, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Phòng chống XML Bomb bằng cách vô hiệu hóa hoàn toàn DTD nội tuyến hoặc giới hạn số lượng mở rộng thực thể tối đa trong cấu hình parser XML.
- **Các bước chi tiết**:
  - Vô hiệu hóa hoàn toàn việc xử lý DTD nội tuyến (Document Type Definitions) trong bộ phân tích cú pháp XML.
  - Vô hiệu hóa tính năng phân giải thực thể XML bên ngoài (XXE).
  - Nếu DTD là bắt buộc đối với nghiệp vụ, hãy thiết lập giới hạn chặt chẽ về số lượng thực thể tối đa được phép mở rộng, kích thước tối đa của thuộc tính và kích thước tổng thể của tệp đầu vào.
  - Nếu nghiệp vụ không cần DTD/XML, dùng định dạng đơn giản hơn có thể loại bỏ vector entity expansion; mọi định dạng vẫn cần giới hạn kích thước, độ sâu và thời gian xử lý.

## 12. Retest

- **Positive case:** với XML Bombs, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của XML Bombs mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Kết luận lỗ hổng tồn tại khi chưa lưu lại nguồn, phiên bản fixture và bằng chứng quan sát được.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim kỹ thuật nhạy cảm có nguồn tham khảo ở mục 17 và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **XML Entity (Thực thể XML)**: Hoạt động như một biến hoặc một lối tắt thay thế cho đoạn văn bản dài hơn trong tài liệu XML.
- **DTD (Document Type Definition)**: Định nghĩa kiểu tài liệu, dùng để quy định cấu trúc ngữ pháp và các thực thể hợp lệ được sử dụng trong tệp XML.
- **XML Parser**: Bộ phân tích cú pháp XML, chịu trách nhiệm đọc và biên dịch tệp XML thành cấu trúc dữ liệu mà ứng dụng hiểu được.
- **Entity Expansion (Mở rộng thực thể)**: Quá trình thay thế các thực thể viết tắt bằng giá trị văn bản thực tế của chúng trong khi xử lý XML.
- **Out of Memory (OOM)**: Lỗi cạn kiệt bộ nhớ RAM của hệ thống, khiến ứng dụng hoặc máy chủ bị tắt đột ngột do không thể cấp phát thêm bộ nhớ.
- **Billion Laughs (Một tỷ tiếng cười)**: Tên gọi phổ biến của cuộc tấn công XML Bomb, xuất phát từ việc lặp lại đệ quy thực thể mang giá trị "lol" (viết tắt của cười lớn) lên đến một tỷ lần.
- **Defusedxml**: Thư viện Python an toàn dùng để thay thế bộ parser XML mặc định, tự động chặn đứng các cuộc tấn công XML Bomb và chèn thực thể bên ngoài.

## 16. Bài liên quan và đọc thêm

- [XML External Entities](../../05-injection/xxe/) — Lỗ hổng chèn thực thể XML bên ngoài cho phép đọc file hệ thống hoặc thực hiện SSRF thay vì gây cạn kiệt tài nguyên máy chủ.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-776. https://cwe.mitre.org/data/definitions/776.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE-400. https://cwe.mitre.org/data/definitions/400.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** Python XML Processing Modules — XML vulnerabilities. https://docs.python.org/3/library/xml.html#xml-vulnerabilities — phiên bản/trạng thái: Python 3.x; truy cập: 2026-07-18.
- **[S5]** defusedxml documentation. https://github.com/tiran/defusedxml — phiên bản/trạng thái: 0.7.1; truy cập: 2026-07-18.
