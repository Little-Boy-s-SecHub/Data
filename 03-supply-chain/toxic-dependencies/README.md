# Toxic Dependencies

> **CWE**: CWE-1395 (Dependency on Vulnerable Third-Party Component) | **Phân loại**: Supply Chain

## Kiến thức Nền tảng
Hãy tưởng tượng bạn đang mở một nhà hàng lẩu. Thay vì tự đi cấy lúa, tự nuôi bò hay trồng rau, bạn nhập rau từ một nông trại, nhập thịt từ một lò mổ và nhập nước sốt đóng chai từ một công ty gia vị. Việc này giúp nhà hàng của bạn vận hành nhanh chóng và phục vụ được nhiều món ăn đa dạng. Thế nhưng, nếu chai nước sốt bạn nhập về bị nhiễm khuẩn độc hại mà bạn không hề kiểm tra trước khi đổ vào nồi lẩu cho khách, toàn bộ thực khách của bạn sẽ bị ngộ độc. 

Trong lập trình cũng vậy, các chai nước sốt đó chính là các **thư viện phụ thuộc (dependencies)** do bên thứ ba phát triển. Để quản lý chúng, lập trình viên sử dụng các kho lưu trữ trực tuyến (registry) và trình quản lý gói để tải mã nguồn về. Khi bạn tải một thư viện, thư viện đó lại tải tiếp các thư viện nhỏ hơn khác, tạo thành một **cây phụ thuộc (dependency tree)** chằng chịt. Nếu chỉ một nhánh nhỏ nằm sâu dưới cùng của cây phụ thuộc này chứa mã lỗi hoặc bị kẻ xấu chèn độc (gọi là **Toxic Dependencies**), toàn bộ ứng dụng lớn của bạn cũng sẽ bị nhiễm độc theo. Để theo dõi các "dịch bệnh" phần mềm này, thế giới sử dụng hệ thống mã định danh lỗ hổng **CVE** giúp cảnh báo kịp thời cho cộng đồng.

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

## Mô tả lỗ hổng
Lỗ hổng **Thư viện nhiễm độc** (Toxic Dependencies hoặc Vulnerable Components) xảy ra khi ứng dụng tích hợp các thư viện bên thứ ba đã quá cũ, không còn được bảo trì, hoặc chứa các lỗi bảo mật nghiêm trọng đã được công bố công khai nhưng chưa được cập nhật.

Mối nguy hiểm của lỗ hổng này cực kỳ lớn vì các lập trình viên thường chỉ tập trung viết mã nguồn của mình mà rất ít khi rà soát hàng ngàn dòng mã của các thư viện bên ngoài tải về. Kẻ tấn công có thể dễ dàng dò quét hệ thống của bạn để tìm ra các thư viện lỗi thời này thông qua các mã lỗi công khai (CVE). Sau đó, chúng chỉ cần gửi các yêu cầu đặc biệt được thiết kế để kích hoạt lỗi có sẵn trong thư viện đó (ví dụ như lỗ hổng nổi tiếng Heartbleed hoặc Log4Shell) để đánh cắp các dữ liệu nhạy cảm trong bộ nhớ RAM, đọc trộm cấu hình hệ thống, hoặc trực tiếp kiểm soát toàn bộ máy chủ của bạn từ xa.

## Cơ chế tấn công
Kẻ tấn công xác định các thư viện bên thứ ba bị lỗi hoặc có lỗ hổng bảo mật đã được công bố (CVE) trong hệ thống của nạn nhân. Chúng gửi các payload được thiết kế chuyên biệt để kích hoạt lỗ hổng của thư viện đó. Ví dụ, với lỗ hổng Heartbleed, kẻ tấn công gửi yêu cầu heartbeat quá khổ mà không kiểm tra độ dài dữ liệu, khiến máy chủ OpenSSL phản hồi bằng cách sao chép các vùng dữ liệu ngẫu nhiên từ RAM chứa các khóa bí mật hoặc thông tin đăng nhập thô của người dùng.

### Ví dụ 3 bước khai thác CVE từ Toxic Dependency:
```bash
# Bước 1: Kẻ tấn công phát hiện dependency cũ có CVE
npm audit
# OUTPUT:
# lodash  4.17.4  Prototype Pollution  CVE-2019-10744  HIGH
# Packages: 1 vulnerable

# Bước 2: Khai thác CVE-2019-10744 (Prototype Pollution trong lodash)
const _ = require('lodash')  # version 4.17.4
_.merge({}, JSON.parse('{"__proto__": {"admin": true}}'))
console.log({}.admin)  # true — toàn bộ objects bị nhiễm

# Bước 3: Hậu quả — bypass authorization check
if (user.admin) {  # true với mọi user do prototype pollution
  grantAdminAccess()
}
```

## Biện pháp phòng thủ
- **Tóm tắt**: Phòng chống các thư viện độc hại và lỗi thời bằng việc quét lỗ hổng liên tục, ghim cứng phiên bản, sử dụng các lockfile và duy trì các registry nội bộ được phê duyệt.
- **Các bước chi tiết**:
  - Quét liên tục các thư viện phụ thuộc của dự án để phát hiện các lỗ hổng đã biết bằng các công cụ như OWASP Dependency-Check, Snyk, hoặc npm audit.
  - Ghim các thư viện phụ thuộc vào một phiên bản cố định cụ thể và sử dụng các file khóa (như `package-lock.json`, `poetry.lock`, `Cargo.lock`) để đảm bảo quá trình build luôn nhất quán.
  - Thực hiện xác thực mã băm (integrity hash validation) cho các gói thư viện để phát hiện trường hợp mã nguồn thư viện bị thay đổi trái phép.
  - Sử dụng các repository/registry nội bộ được phê duyệt (như Artifactory, Nexus) để quản lý các dependency trước khi đưa vào ứng dụng.
  - Thiết lập quy trình xem xét và kiểm tra uy tín, giấy phép của thư viện mới trước khi thêm vào dự án.

## Code Example
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


## Xem thêm
- [Malvertising](../malvertising/) — Xem thêm bài học về Malvertising.

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP Top 10 A06:2021, CWE-1395

## Giải thích thuật ngữ
- **Registry**: Kho lưu trữ phần mềm trực tuyến trung tâm nơi các lập trình viên có thể chia sẻ và tải về các gói mã nguồn (ví dụ: npmjs.com, PyPI).
- **Dependency Tree (Cây phụ thuộc)**: Cấu trúc phân cấp biểu thị mối quan hệ giữa ứng dụng của bạn và tất cả các thư viện lớn nhỏ mà nó cần tải về để hoạt động.
- **CVE (Common Vulnerabilities and Exposures)**: Danh sách chuẩn hóa toàn cầu giúp định danh và theo dõi các lỗ hổng bảo mật đã công bố công khai.
- **Toxic Dependencies**: Các thư viện bên thứ ba được sử dụng trong dự án nhưng chứa mã độc hại hoặc lỗ hổng bảo mật nghiêm trọng.
- **Heartbleed**: Lỗ hổng bảo mật cực kỳ nghiêm trọng trong thư viện mã hóa OpenSSL (CVE-2014-0160), cho phép kẻ tấn công đọc bộ nhớ của máy chủ để lấy cắp khóa bí mật và dữ liệu người dùng.
- **Log4Shell**: Lỗ hổng thực thi mã từ xa đặc biệt nguy hiểm trong thư viện ghi nhật ký Apache Log4j của Java (CVE-2021-44228).
- **Hash/Integrity Hash**: Mã băm dùng để kiểm tra tính toàn vẹn của tệp tin, đảm bảo tệp tải về trùng khớp hoàn toàn với bản gốc và không bị sửa đổi.
