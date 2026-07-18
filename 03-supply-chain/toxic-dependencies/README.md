---
schema_version: 1
id: WEB-A03-TOXIC-DEPENDENCIES
title: "Toxic Dependencies"
slug: toxic-dependencies
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A03:2025
cwe:
  - CWE-1395
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Toxic Dependencies

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Toxic Dependencies bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Direct/transitive dependency và package registry.

- Version range, lockfile, reachability và lifecycle script.

- Sandbox Node.js fixture không có outbound network.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn đang mở một nhà hàng lẩu. Thay vì tự đi cấy lúa, tự nuôi bò hay trồng rau, bạn nhập rau từ một nông trại, nhập thịt từ một lò mổ và nhập nước sốt đóng chai từ một công ty gia vị. Việc này giúp nhà hàng của bạn vận hành nhanh chóng và phục vụ được nhiều món ăn đa dạng. Thế nhưng, nếu chai nước sốt bạn nhập về bị nhiễm khuẩn độc hại mà bạn không hề kiểm tra trước khi đổ vào nồi lẩu cho khách, toàn bộ thực khách của bạn sẽ bị ngộ độc. [S3]

Trong lập trình cũng vậy, các chai nước sốt đó chính là các **thư viện phụ thuộc (dependencies)** do bên thứ ba phát triển. Để quản lý chúng, lập trình viên sử dụng các kho lưu trữ trực tuyến (registry) và trình quản lý gói để tải mã nguồn về. Khi bạn tải một thư viện, thư viện đó lại tải tiếp các thư viện nhỏ hơn khác, tạo thành một **cây phụ thuộc (dependency tree)** chằng chịt. Nếu chỉ một nhánh nhỏ nằm sâu dưới cùng của cây phụ thuộc này chứa mã lỗi hoặc bị kẻ xấu chèn độc (gọi là **Toxic Dependencies**), toàn bộ ứng dụng lớn của bạn cũng sẽ bị nhiễm độc theo. Để theo dõi các "dịch bệnh" phần mềm này, thế giới sử dụng hệ thống mã định danh lỗ hổng **CVE** giúp cảnh báo kịp thời cho cộng đồng. [S3]

### Minh họa hoạt động bình thường (Normal Operation)

Ví dụ `package.json` hợp lệ dưới đây ghim dependency trực tiếp và cung cấp lệnh audit; JSON chuẩn không hỗ trợ comment. File này chưa khóa toàn bộ dependency bắc cầu hay artifact digest: repository vẫn cần commit/review `package-lock.json` và CI dùng `npm ci`. [S3]

```json
{
  "name": "secure-app",
  "version": "1.0.0",
  "scripts": {
    "audit": "npm audit --audit-level=high"
  },
  "dependencies": {
    "express": "4.19.2",
    "lodash": "4.17.21"
  }
}
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Thư viện nhiễm độc** (Toxic Dependencies hoặc Vulnerable Components) xảy ra khi ứng dụng tích hợp các thư viện bên thứ ba đã quá cũ, không còn được bảo trì, hoặc chứa các lỗi bảo mật nghiêm trọng đã được công bố công khai nhưng chưa được cập nhật. [S3]

Mối nguy hiểm của lỗ hổng này cực kỳ lớn vì các lập trình viên thường chỉ tập trung viết mã nguồn của mình mà rất ít khi rà soát hàng ngàn dòng mã của các thư viện bên ngoài tải về. Kẻ tấn công có thể dễ dàng dò quét hệ thống của bạn để tìm ra các thư viện lỗi thời này thông qua các mã lỗi công khai (CVE). Sau đó, chúng chỉ cần gửi các yêu cầu đặc biệt được thiết kế để kích hoạt lỗi có sẵn trong thư viện đó (ví dụ như lỗ hổng nổi tiếng Heartbleed hoặc Log4Shell) để đánh cắp các dữ liệu nhạy cảm trong bộ nhớ RAM, đọc trộm cấu hình hệ thống, hoặc trực tiếp kiểm soát toàn bộ máy chủ của bạn từ xa. [S3]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** runtime Node.js disposable và dependency graph của ứng dụng.

- **Actor:** input synthetic đi vào API dễ lỗi của lodash 4.17.4; không lấy payload Internet.

- **Trust boundary:** JSON.parse và defaultsDeep thay đổi object/prototype trong cùng process.

- **Điều kiện cần:** đúng version/path dễ lỗi được gọi; process chưa được cô lập/loại bỏ sau test.

- **Môi trường:** Node.js 12.x container, local registry, outbound disabled.

Chỉ advisory/CVE match chưa đủ: cần xác nhận version reachable và marker LAB_POLLUTED trong process disposable. [S3], [S4]

## 6. Cơ chế tấn công

Ứng dụng gọi API reachable của đúng dependency/version dễ lỗi. Input synthetic kích hoạt behavior trong process, như prototype pollution; advisory không reachable không tạo cùng cơ chế. [S3], [S4]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** build container Node 12.x với lodash 4.17.4 từ registry lab; snapshot rồi chặn outbound.
2. **Baseline:** object mới không có thuộc tính labPolluted.
3. **Thao tác:** chạy đúng JSON constructor path một lần trong process giới hạn.
4. **Expected result:** version lỗi in LAB_POLLUTED=true; version sửa không pollute và test regression pass.
5. **Boundary:** kiểm tra API/path khác chỉ khi source xác nhận; không suy rộng mọi lodash version.
6. **Cleanup:** terminate/discard toàn bộ process và container.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review.

`static-verified` chỉ xác nhận cấu trúc và annotation đã qua gate tĩnh.

Trạng thái này không chứng minh payload hoạt động trên mọi phiên bản.

Trước khi chạy, phải đối chiếu context, điều kiện, encoding, expected result và risk.

Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Kẻ tấn công có thể kích hoạt một lỗi cụ thể khi ứng dụng thực sự cài phiên bản bị ảnh hưởng và dữ liệu do actor kiểm soát đi đến API dễ lỗi. Ví dụ lab bên dưới pin lodash 4.17.4 và dùng `defaultsDeep`; CVE-2019-10744 ảnh hưởng lodash trước 4.17.12 qua constructor payload. Không được suy từ tên package hoặc CVE sang khả năng khai thác mà thiếu version và call path. [S3], [S4]

### Ví dụ 3 bước khai thác CVE từ Toxic Dependency:
<!-- payload-id: WEB-A03-TOXIC-DEPENDENCIES-001 -->
<!-- context: Node.js 12.x disposable process; lodash 4.17.4; defaultsDeep constructor path; documented vulnerable-version behavior [S3] -->
<!-- prerequisites: install only from the lab registry with outbound network disabled -->
<!-- encoding: UTF-8 JavaScript source; the JSON string is parsed once with no URL or transport decoding -->
<!-- expected-result: the isolated process prints LAB_POLLUTED=true, then exits and the container is discarded -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S3,S4 -->
<!-- last-verified: 2026-07-17 -->
```javascript
// CVE-2019-10744 affects lodash versions below 4.17.12 via defaultsDeep
const defaultsDeep = require('lodash').defaultsDeep;
const payload = '{"constructor":{"prototype":{"labPolluted":true}}}';

defaultsDeep({}, JSON.parse(payload));
console.log(`LAB_POLLUTED=${({}).labPolluted === true}`);

// End the disposable process; never reuse a polluted runtime
delete Object.prototype.labPolluted;
```

## 9. Code dễ bị lỗi và code an toàn

```json
{
  "name": "vulnerable-fixture",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.4"
  }
}
```

```json
{
  "name": "secure-app",
  "version": "1.0.0",
  "scripts": {
    "audit": "npm audit --audit-level=high"
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

Manifest ghim version trực tiếp chưa khóa dependency bắc cầu. Repository phải commit/review `package-lock.json`; CI dùng `npm ci` để từ chối khi manifest lệch lockfile và không tự sửa lockfile. Việc nâng version chỉ xử lý CVE khi advisory và regression test xác nhận call path bị ảnh hưởng đã được loại bỏ. [S3], [S5]

## 10. Phát hiện

- Xác nhận exact artifact/version và gọi đúng code path trong fixture; CVE match đơn thuần chưa đủ reachability. [S3]

- Review transitive graph, install script, publisher/provenance và hành vi runtime. [S3]

- Thu process/file/network event trong container disposable; không cấp secret.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Pin/review artifact và provenance; loại hoặc nâng dependency có hành vi/rủi ro không chấp nhận được. [S3]

- Chạy dependency không tin cậy trong môi trường build bị cô lập, không có credential/outbound mặc định. [S3]

### Defense-in-depth

- SCA và reachability analysis hỗ trợ ưu tiên remediation.

- Runtime sandbox giảm blast radius nhưng không làm package trở nên tin cậy.

## 12. Retest

- **Positive:** version đã duyệt cài và chạy đúng code path cần thiết.

- **Negative:** artifact/digest ngoài policy bị chặn trước execution.

- **Boundary:** transitive version, optional dependency, platform và lockfile drift.

- **Telemetry:** xác nhận package graph, process spawn, file write và egress.

## 13. Sai lầm thường gặp

- Gọi mọi dependency có CVE là exploitable trong ứng dụng.

- Tin lockfile tự chứng minh publisher hoặc tính vô hại.

- Test package nghi ngờ trên host có credential.

- Chỉ nâng direct dependency mà không xác nhận transitive version đã đổi.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim nhạy cảm có source marker và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **Dependency graph:** tập direct/transitive package được resolver chọn cho build. [S5]

- **Known-vulnerable component:** component/version có bản ghi lỗ hổng công khai như CVE. [S3]

- **Lockfile:** bản ghi dependency resolution mà `npm ci` dùng và kiểm tra với manifest. [S5]

## 16. Bài liên quan và đọc thêm

- [Malvertising](../malvertising/) — Xem thêm bài học về Malvertising.

## 17. Tài liệu tham khảo

- **[S3]** NIST NVD — CVE-2019-10744. https://nvd.nist.gov/vuln/detail/CVE-2019-10744 — phiên bản/trạng thái: bản ghi hiện hành; truy cập: 2026-07-17.
- **[S4]** Snyk Advisory — Prototype Pollution in lodash. https://security.snyk.io/vuln/SNYK-JS-LODASH-450202 — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S5]** npm CLI documentation — `npm ci`. https://docs.npmjs.com/cli/commands/npm-ci/ — phiên bản/trạng thái: tài liệu hiện hành; truy cập: 2026-07-18.
