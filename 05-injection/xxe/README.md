# XML External Entities

> **OWASP Top 10:2025**: A05:2025 – Injection | **CWE**: CWE-611 (Improper Restriction of XML External Entity Reference) | **Phân loại**: Injection

## 🧱 Kiến thức Nền tảng
XML (eXtensible Markup Language) là ngôn ngữ đánh dấu dùng để lưu trữ và truyền tải dữ liệu có cấu trúc. Một tài liệu XML tiêu chuẩn bao gồm phần khai báo XML (XML declaration), phần tử gốc (root element), và các phần tử con lồng nhau. Để định nghĩa cấu trúc dữ liệu hợp lệ, XML sử dụng DTD (Document Type Definition). DTD cho phép định nghĩa các thực thể (Entities), hoạt động giống như các biến số trong lập trình. Khi bộ phân tích cú pháp XML (XML parser) gặp một thực thể, nó sẽ thay thế thực thể đó bằng giá trị tương ứng. XML hỗ trợ thực thể bên ngoài (External Entities), cho phép tải dữ liệu từ các tài nguyên bên ngoài hệ thống bằng cách sử dụng các chỉ thị định danh hệ thống (SYSTEM identifier) trỏ tới các giao thức mạng hoặc tệp tin cục bộ (ví dụ: `file:///etc/passwd`).

Lỗ hổng XML External Entity (XXE) xảy ra khi bộ phân tích cú pháp XML được cấu hình lỏng lẻo xử lý các thực thể bên ngoài do người dùng cung cấp trong tài liệu XML. Kẻ tấn công có thể chèn các thực thể trỏ đến các tệp nhạy cảm trên máy chủ hoặc các địa chỉ IP nội bộ để thực hiện tấn công SSRF. Để ngăn chặn XXE, giải pháp an toàn và hiệu quả nhất là cấu hình bộ phân tích cú pháp XML để vô hiệu hóa hoàn toàn tính năng khai báo DTD (`disallow-doctype-decl`). Nếu DTD là bắt buộc đối với ứng dụng, lập trình viên phải tắt tính năng phân giải thực thể bên ngoài (cả thực thể chung và thực thể tham số) cũng như việc tải các DTD bên ngoài. Sử dụng các thư viện an toàn mặc định hoặc cấu hình tường lửa ứng dụng (WAF) để lọc các yêu cầu chứa thẻ `DOCTYPE` cũng là các biện pháp bổ trợ hữu ích.

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

## 🔍 Mô tả lỗ hổng
XML External Entity (XXE) xảy ra khi bộ phân tích cú pháp XML cấu hình yếu kém xử lý các thực thể bên ngoài (external entities) do người dùng cung cấp trong tài liệu XML. Kẻ tấn công có thể lợi dụng điều này để đọc các tệp tin cục bộ nhạy cảm trên máy chủ, thực hiện quét cổng nội bộ, hoặc thực hiện các yêu cầu giả mạo phía máy chủ (SSRF). Lỗ hổng này cực kỳ nguy hiểm và thường xuất hiện ở các thư viện phân tích XML cũ không tắt chế độ DTD.

## ⚔️ Cơ chế tấn công
Kẻ tấn công tải lên hoặc gửi một tài liệu XML chứa thực thể trỏ đến một đường dẫn tệp hệ thống bằng cách sử dụng các giao thức như `file:///` hoặc `http://` (ví dụ: `<!ENTITY passwords SYSTEM "file:///etc/passwd">`). Khi bộ phân tích cú pháp của máy chủ xử lý thực thể này, nó sẽ mở rộng thực thể bằng cách tải nội dung tệp `/etc/passwd` và chèn vào dữ liệu XML. Nếu ứng dụng hiển thị lại nội dung XML này trong phản hồi lỗi hoặc dữ liệu phản hồi, kẻ tấn công sẽ đọc được toàn bộ nội dung tệp nhạy cảm đó.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Ngăn chặn XXE một cách triệt để bằng cách cấu hình bộ phân tích cú pháp XML để vô hiệu hóa hoàn toàn DTD và các thực thể bên ngoài.
- **Các bước chi tiết**:
  - Cấu hình bộ phân tích cú pháp XML để tắt chỉ thị Disallow Doctype Decl (khai báo DTD) hoặc tắt hoàn toàn việc phân giải External Entities (External Subset / Parameter Entities).
  - Xác minh rằng các thư viện sử dụng gián tiếp XML (SOAP clients, bộ xử lý ảnh SVG, thư viện đọc tài liệu Office) cũng đã được tắt tính năng phân giải thực thể bên ngoài.
  - Thực hiện kiểm tra và xác thực cấu trúc lược đồ XML (XSD) trước khi bắt đầu xử lý tệp.
  - Triển khai Tường lửa ứng dụng Web (WAF) để lọc và phát hiện các payload XXE đặc trưng gửi lên hệ thống.

## 💻 Code Example
```java
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

public class SecureXMLParser {
    public static DocumentBuilderFactory getSecureFactory() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        
        // Disable DTDs entirely (highly recommended)
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        
        // Alternatively, if DTDs are required, disable external entity resolution:
        // dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        // dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        // dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        
        return dbf;
    }
}
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Trong ví dụ Java, các ký tự chú thích `#` (kiểu Python) gây lỗi biên dịch đã được thay thế bằng chú thích hợp lệ `//`. Đồng thời điều chỉnh tệp nhạy cảm trong ví dụ payload ở Slide 9 từ tệp đòi hỏi quyền root `/etc/shadow` thành tệp `/etc/passwd` thực tế hơn, và sửa cú pháp đường dẫn URI bị lỗi từ `file://etc/shadow` thành `file:///etc/passwd` chuẩn.
- **Nguồn tham khảo**: OWASP XXE Cheat Sheet, PortSwigger, CWE-611
