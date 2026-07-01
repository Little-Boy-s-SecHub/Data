# Malvertising

> **CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) | **Phân loại**: Supply Chain

## Kiến thức Nền tảng
Hãy tưởng tượng bạn sở hữu một tòa soạn báo điện tử lớn và uy tín. Để có thêm doanh thu duy trì hoạt động, bạn ký hợp đồng với một đại lý quảng cáo trung gian, cho phép họ treo một bảng hiệu điện tử động ở một góc trang báo. Đại lý này sẽ tự động thay đổi nội dung quảng cáo sau mỗi vài giây (gọi là **kiến trúc mạng lưới quảng cáo - ad network architecture**). Nội dung hiển thị trên bảng hiệu đó được tải trực tiếp từ máy chủ của đại lý, tòa soạn của bạn hoàn toàn không thể kiểm soát hay duyệt trước từng hình ảnh hoặc đoạn video được đưa lên.

Một ngày nọ, kẻ xấu hack được vào máy chủ của đại lý quảng cáo kia, hoặc đóng giả làm một khách hàng mua quảng cáo hợp pháp. Thay vì gửi lên một bức ảnh giới thiệu sản phẩm thông thường, chúng lại lén chèn vào đó một đoạn mã độc JavaScript (gọi là **nhúng mã kịch bản bên thứ ba - third-party script embedding**). Khi độc giả truy cập vào trang báo của bạn, trình duyệt của họ sẽ tự động tải đoạn mã độc này từ bảng hiệu quảng cáo về và chạy ngay lập tức. Vì đoạn mã chạy trực tiếp trên trình duyệt của người dùng dưới danh nghĩa trang báo uy tín của bạn, nó có thể âm thầm đọc trộm cookie phiên làm việc, tự động tải phần mềm độc hại về máy người dùng, hoặc đột ngột chuyển hướng họ sang một trang web lừa đảo.

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

## Mô tả lỗ hổng
Lỗ hổng **Quảng cáo độc hại** (Malvertising) xảy ra khi một trang web tin cậy tích hợp các đoạn mã hoặc khung hiển thị quảng cáo từ bên thứ ba mà không áp dụng các biện pháp cô lập bảo vệ cần thiết.

Mối nguy hiểm của Malvertising nằm ở chỗ nó phá vỡ tính toàn vẹn của ứng dụng web thông qua một con đường hoàn toàn hợp pháp. Chủ sở hữu trang web thường tin tưởng tuyệt đối vào các mạng lưới quảng cáo lớn, trong khi các mạng lưới này lại phân phối nội dung vô cùng năng động và khó kiểm soát. Nếu không sử dụng các cơ chế cô lập như thuộc tính `sandbox` cho thẻ iframe chứa quảng cáo, hoặc thiếu chính sách bảo mật nội dung (CSP) nghiêm ngặt để giới hạn nguồn chạy script, trang web của bạn sẽ vô tình trở thành bệ phóng giúp kẻ tấn công phát tán mã độc đến hàng triệu khách hàng tin cậy của mình.

## Cơ chế tấn công
Bước 1: Kẻ tấn công mua một vị trí quảng cáo trên một mạng lưới quảng cáo (ad network) trung gian.
Bước 2: Kẻ tấn công chèn mã JavaScript độc hại vào nội dung quảng cáo thay vì hình ảnh thông thường.
Bước 3: Trang web đáng tin cậy tích hợp script của mạng lưới quảng cáo để hiển thị quảng cáo cho người dùng.
Bước 4: Khi người dùng truy cập trang web, trình duyệt của họ tải quảng cáo độc hại và tự động thực thi script độc hại, chuyển hướng người dùng đến trang lừa đảo hoặc tải xuống malware mà trang web chính không hề hay biết.

## Biện pháp phòng thủ
- **Tóm tắt**: Malvertising (malicious advertising) involves attackers injecting malicious advertisements into legitimate advertising networks. Mitigation focuses on secure ad network integration, strict Content Security Policy (CSP), sandboxing iframes, and vetting third-party scripts.
- **Các bước chi tiết**:
  - Implement a robust Content Security Policy (CSP) to restrict where scripts and resources can be loaded from, limiting exposure to untrusted ad domains.
  - Sandbox iframes hosting third-party advertisements using the 'sandbox' attribute with minimal permissions (e.g., allow-scripts but not allow-top-navigation).
  - Require ad networks to use secure, encrypted communication (HTTPS) and deliver only digitally signed or verified advertisements.
  - Perform continuous monitoring and security vetting of third-party ad networks, their dynamic payloads, and redirection behavior.
  - Use Subresource Integrity (SRI) for static third-party ad scripts to ensure they haven't been tampered with or replaced with malicious versions.

## Code Example
```configuration
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted-ad-provider.com; frame-src https://trusted-ad-provider.com;
```


## Xem thêm
- [Subdomain Squatting](../subdomain-squatting/) — Xem thêm bài học về Subdomain Squatting.

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A06:2021, CWE-829

## Giải thích thuật ngữ
- **Malvertising**: Sự kết hợp của "malicious" (độc hại) và "advertising" (quảng cáo), là hình thức lây truyền mã độc thông qua các quảng cáo trực tuyến.
- **Ad Network Architecture**: Kiến trúc mạng lưới quảng cáo kỹ thuật số kết nối bên mua và bên bán không gian quảng cáo tự động.
- **Third-Party Script**: Các đoạn mã kịch bản do bên thứ ba phát triển và được nhúng trực tiếp vào trang web chính để thực hiện một chức năng cụ thể (như quảng cáo, phân tích số liệu).
- **Subresource Integrity (SRI)**: Cơ chế kiểm tra tính toàn vẹn của tài nguyên phụ, giúp trình duyệt xác minh xem tệp tin tải về từ bên thứ ba có bị sửa đổi hay không bằng cách đối chiếu mã băm (hash).
- **Sandbox Attribute**: Thuộc tính của thẻ iframe giúp giới hạn quyền hạn của trang web được nhúng bên trong (ví dụ: cấm chạy script, cấm tự động chuyển hướng trang).
