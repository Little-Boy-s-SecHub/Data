# Malvertising

> **OWASP Top 10:2025**: A03:2025 – Software Supply Chain Failures | **CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) | **Phân loại**: Software and Data Integrity Failures

## 🧱 Kiến thức Nền tảng
Malvertising (Quảng cáo độc hại) là một phương thức tấn công phức tạp tận dụng chuỗi cung ứng quảng cáo kỹ thuật số để phát tán mã độc. Để hiểu cơ chế phòng chống, chúng ta cần tìm hiểu hai khái niệm kỹ thuật cốt lõi sau:

1. **Ad network architecture (Kiến trúc mạng lưới quảng cáo)**: Đây là hệ thống phân phối quảng cáo tự động kết nối giữa bên mua quảng cáo (advertisers) và bên bán không gian hiển thị (publishers). Quy trình này vận hành thông qua các ad servers trung gian và các phiên đấu giá thời gian thực (Real-Time Hashing/Bidding - RTB) diễn ra trong mili giây khi người dùng tải trang. Vì nội dung quảng cáo được chọn và tải động từ máy chủ của ad network, chủ sở hữu trang web chính không thể kiểm duyệt trực tiếp từng file ảnh hoặc script được đẩy về trình duyệt của khách hàng.
2. **Third-party script embedding (Nhúng mã kịch bản bên thứ ba)**: Để hiển thị quảng cáo hoặc tích hợp các công cụ đo lường, các nhà phát triển thường nhúng trực tiếp các thẻ `<script>` hoặc `<iframe>` từ các máy chủ bên ngoài vào mã HTML của trang web. Khi mã kịch bản bên thứ ba được tải, nó chạy trực tiếp trong ngữ cảnh bảo mật của trình duyệt người dùng. Nếu ad network bị kẻ xấu xâm nhập và phân phối script độc hại, script này sẽ có quyền truy cập cookie, thực thi mã tùy ý, hoặc chuyển hướng người dùng sang các trang web giả mạo.

### Minh họa hoạt động bình thường (Normal Operation)
```html
<!-- Normal operation: Embedding a third-party advertisement safely -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Safe Ad Integration Example</title>
</head>
<body>
    <h1>Welcome to Our Website</h1>
    
    <!-- Safe integration using iframe with strict sandbox restrictions -->
    <!-- allow-scripts allows the ad logic to run, but forbids top-level redirects or cookie access -->
    <iframe src="https://trusted-ad-provider.com/display?zone=123"
            width="300"
            height="250"
            sandbox="allow-scripts"
            style="border:none;">
    </iframe>

    <!-- Embedding a third-party analytics script with Subresource Integrity (SRI) -->
    <!-- This ensures the browser only executes the script if its hash matches the expected value -->
    <script src="https://trusted-ad-provider.com/js/analytics.js"
            integrity="sha384-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2"
            crossorigin="anonymous"
            async>
    </script>
</body>
</html>
```

## 🔍 Mô tả lỗ hổng
Quảng cáo độc hại (Malvertising) là hình thức kẻ tấn công nhúng mã độc vào các mạng lưới quảng cáo hợp pháp để phân phối đến người dùng truy cập trang web tin cậy. Mã độc này thường được thực thi thông qua các thẻ iframe hoặc script của bên thứ ba mà ứng dụng web tích hợp. Để phòng ngừa, ứng dụng cần áp dụng cơ chế cô lập quảng cáo bằng thuộc tính sandbox của iframe và thiết lập chính sách bảo mật nội dung (CSP) nghiêm ngặt.

## ⚔️ Cơ chế tấn công
Bước 1: Kẻ tấn công mua một vị trí quảng cáo trên một mạng lưới quảng cáo (ad network) trung gian.
Bước 2: Kẻ tấn công chèn mã JavaScript độc hại vào nội dung quảng cáo thay vì hình ảnh thông thường.
Bước 3: Trang web đáng tin cậy tích hợp script của mạng lưới quảng cáo để hiển thị quảng cáo cho người dùng.
Bước 4: Khi người dùng truy cập trang web, trình duyệt của họ tải quảng cáo độc hại và tự động thực thi script độc hại, chuyển hướng người dùng đến trang lừa đảo hoặc tải xuống malware mà trang web chính không hề hay biết.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Malvertising (malicious advertising) involves attackers injecting malicious advertisements into legitimate advertising networks. Mitigation focuses on secure ad network integration, strict Content Security Policy (CSP), sandboxing iframes, and vetting third-party scripts.
- **Các bước chi tiết**:
  - Implement a robust Content Security Policy (CSP) to restrict where scripts and resources can be loaded from, limiting exposure to untrusted ad domains.
  - Sandbox iframes hosting third-party advertisements using the 'sandbox' attribute with minimal permissions (e.g., allow-scripts but not allow-top-navigation).
  - Require ad networks to use secure, encrypted communication (HTTPS) and deliver only digitally signed or verified advertisements.
  - Perform continuous monitoring and security vetting of third-party ad networks, their dynamic payloads, and redirection behavior.
  - Use Subresource Integrity (SRI) for static third-party ad scripts to ensure they haven't been tampered with or replaced with malicious versions.

## 💻 Code Example
```configuration
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted-ad-provider.com; frame-src https://trusted-ad-provider.com;
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: PASS
- **Ghi chú kỹ thuật**: Trong Milestone 2, bài học này có trạng thái PASS. Đề xuất các biện pháp phòng vệ như giới hạn quyền của iframes chứa quảng cáo bằng thuộc tính sandbox, triển khai Content Security Policy (CSP) chặt chẽ, và kiểm tra tính toàn vẹn của thư viện bên thứ ba.
- **Nguồn tham khảo**: OWASP A06:2021, CWE-829
