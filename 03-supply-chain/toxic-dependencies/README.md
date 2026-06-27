# Toxic Dependencies

> **OWASP Top 10:2025**: A03:2025 – Software Supply Chain Failures | **CWE**: CWE-1395 (Dependency on Vulnerable Third-Party Component) | **Phân loại**: System

## 🧱 Kiến thức Nền tảng
Trong phát triển phần mềm hiện đại, việc sử dụng các thư viện bên thứ ba (dependencies) giúp tăng tốc độ phát triển nhưng cũng đi kèm rủi ro bảo mật lớn nếu không được quản lý chặt chẽ. Để hiểu về lỗ hổng Toxic Dependencies, ta cần nắm rõ ba khái niệm cốt lõi:

1. **npm/pip registry**: Đây là các kho lưu trữ trực tuyến trung tâm (như npmjs.com cho JavaScript hoặc PyPI cho Python) chứa hàng triệu gói mã nguồn (packages) do cộng đồng đóng góp. Các nhà phát triển có thể dễ dàng xuất bản gói của mình hoặc tải các gói có sẵn về máy thông qua các dòng lệnh đơn giản.
2. **Package manager dependency tree (Cây phụ thuộc)**: Khi một dự án sử dụng các gói bên ngoài, trình quản lý gói (npm, pip) sẽ tạo ra một cây phụ thuộc. Cây này biểu diễn mối liên hệ phân cấp từ các thư viện được khai báo trực tiếp (direct dependencies) đến các thư viện mà chính các gói đó cần sử dụng (transitive/indirect dependencies). Một lỗ hổng nằm ở bất kỳ nhánh nào sâu trong cây phụ thuộc đều có thể thỏa hiệp toàn bộ ứng dụng.
3. **CVE (Common Vulnerabilities and Exposures)**: Là hệ thống danh mục chuẩn hóa toàn cầu dùng để định danh và theo dõi các lỗ hổng bảo mật đã được công bố công khai trong phần mềm. Mỗi lỗ hổng được gán một mã CVE duy nhất (như CVE-2021-44228 của Log4Shell), đi kèm mô tả chi tiết và mức độ nghiêm trọng (CVSS), giúp lập trình viên nhận diện và cập nhật kịp thời các gói thư viện bị lỗi.

### Minh họa hoạt động bình thường (Normal Operation)
```json
{
  // A standard package.json file with pinned dependencies and audit script
  "name": "secure-app",
  "version": "1.0.0",
  "scripts": {
    // Run npm audit during normal development to scan for known vulnerabilities
    "audit": "npm audit --audit-level=high"
  },
  "dependencies": {
    // Pinned exact versions to prevent automatic updates to unverified or toxic releases
    "express": "4.19.2",
    "lodash": "4.17.21"
  }
}
```

## 🔍 Mô tả lỗ hổng
Lỗ hổng xảy ra khi ứng dụng tích hợp các thư viện bên thứ ba bị lỗi thời hoặc chứa các lỗ hổng bảo mật đã biết (ví dụ lỗ hổng Heartbleed của OpenSSL hoặc Log4Shell trong Log4j). Do các nhà phát triển thường ít rà soát mã nguồn thư viện ngoài, kẻ tấn công có thể khai thác các điểm yếu này để thực thi mã từ xa, đánh cắp thông tin nhạy cảm từ bộ nhớ RAM hoặc chiếm quyền kiểm soát máy chủ.

## ⚔️ Cơ chế tấn công
Kẻ tấn công xác định các thư viện bên thứ ba bị lỗi hoặc có lỗ hổng bảo mật đã được công bố (CVE) trong hệ thống của nạn nhân. Chúng gửi các payload được thiết kế chuyên biệt để kích hoạt lỗ hổng của thư viện đó. Ví dụ, với lỗ hổng Heartbleed, kẻ tấn công gửi yêu cầu heartbeat quá khổ mà không kiểm tra độ dài dữ liệu, khiến máy chủ OpenSSL phản hồi bằng cách sao chép các vùng dữ liệu ngẫu nhiên từ RAM chứa các khóa bí mật hoặc thông tin đăng nhập thô của người dùng.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Phòng chống các thư viện độc hại và lỗi thời bằng việc quét lỗ hổng liên tục, ghim cứng phiên bản, sử dụng các lockfile và duy trì các registry nội bộ được phê duyệt.
- **Các bước chi tiết**:
  - Quét liên tục các thư viện phụ thuộc của dự án để phát hiện các lỗ hổng đã biết bằng các công cụ như OWASP Dependency-Check, Snyk, hoặc npm audit.
  - Ghim các thư viện phụ thuộc vào một phiên bản cố định cụ thể và sử dụng các file khóa (như `package-lock.json`, `poetry.lock`, `Cargo.lock`) để đảm bảo quá trình build luôn nhất quán.
  - Thực hiện xác thực mã băm (integrity hash validation) cho các gói thư viện để phát hiện trường hợp mã nguồn thư viện bị thay đổi trái phép.
  - Sử dụng các repository/registry nội bộ được phê duyệt (như Artifactory, Nexus) để quản lý các dependency trước khi đưa vào ứng dụng.
  - Thiết lập quy trình xem xét và kiểm tra uy tín, giấy phép của thư viện mới trước khi thêm vào dự án.

## 💻 Code Example
```json
{
  "name": "secure-app",
  "version": "1.0.0",
  "scripts": {
    "audit": "npm audit --audit-level=high",
    "prepublishOnly": "npm ci"
  },
  "dependencies": {
    "express": "4.19.2",
    "lodash": "4.17.21"
  },
  "overrides": {
    "lodash": "4.17.21"
  }
}
```

Ví dụ ghim mã hash trong file `requirements.txt` của Python:
```configuration
# python pip requirements.txt with sha256 hashes
requests==2.31.0 --hash=sha256:58cd2187c01e72ec6d56e7555e011162c2f704b40d6c1be7d28d04e3ab75b282 \
                 --hash=sha256:942c5a758f98d7572d6ec6e3402d076d73400999035f5db83c9226d74e0b5e55
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã sửa lỗi chính tả ở Slide 10 phần kết quả hiển thị hex dump của gói tin Heartbleed, trong đó tiền tố offset dòng `0050` bị lặp lại sau `0060`. Trình tự offset đã được chuẩn hóa thành `0070`, `0080`, `0090` để hiển thị chính xác.
- **Nguồn tham khảo**: OWASP Top 10 A06:2021, CWE-1395
