---
schema_version: 1
id: WEB-A08-PROTOTYPE-POLLUTION
title: "Prototype Pollution"
slug: prototype-pollution
level: advanced
estimated_minutes: 65
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  []
cwe:
  - CWE-1321
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Prototype Pollution

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Prototype Pollution bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống Prototype Pollution và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

JavaScript có cơ chế kế thừa nguyên mẫu: khi một thuộc tính không tồn tại trực tiếp trên object, runtime có thể tiếp tục tra cứu dọc chuỗi nguyên mẫu. Một accessor lịch sử cho phép quan sát hoặc thay đổi liên kết này, nhưng application code không nên dùng accessor đó làm API dữ liệu. [S1]

Khi code đọc một thuộc tính, runtime kiểm tra own property trước rồi mới đi qua các prototype cha cho đến khi hết chuỗi. Vì vậy kiểm tra quyền hoặc cấu hình bằng một property kế thừa có thể nhận giá trị không thuộc chính object nghiệp vụ. [S1]

Vì `Object.prototype` là cụ tổ tối cao, nên bất cứ thứ gì cụ tổ sở hữu (như các hàm cơ bản `toString` hay `hasOwnProperty`), tất cả con cháu sinh ra đời sau đều mặc nhiên được thừa hưởng.

Prototype Pollution khai thác hàm merge hoặc setter đệ quy cho phép input chọn các khóa điều khiển prototype. Nếu sink sửa prototype dùng chung, các object khác có thể kế thừa property ngoài ý định. Tác động không tự động là XSS, bypass hay RCE: cần một gadget riêng đọc property bị ô nhiễm vào security decision hoặc dangerous sink. Payload và marker kiểm chứng được giữ ở mục 8. [S1] [S3]

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Prototype Pollution (Ô nhiễm nguyên mẫu)** xảy ra khi input không tin cậy đi vào phép gán hoặc merge cho phép chạm tới prototype dùng chung. Root cause là thiếu kiểm soát khóa ở mọi độ sâu và sau đó tin vào property kế thừa; danh sách khóa và input kiểm thử cụ thể chỉ nằm ở mục 8–9. [S1] [S3]

Khi cụ tổ đã bị nhiễm độc, hành vi của toàn bộ hệ thống JavaScript sẽ bị xoay chuyển. Kẻ tấn công có thể lợi dụng điều này để:
- Vượt qua các chốt kiểm tra quyền hạn (ví dụ tự động gán vai trò quản trị viên cho mọi đối tượng người dùng).
- Chèn các đoạn mã script nguy hại để tấn công người dùng trực tiếp trên trình duyệt (Client-side XSS).
- Chiếm quyền điều khiển máy chủ và chạy các câu lệnh hệ thống từ xa (RCE) nếu ứng dụng chạy trên nền Node.js.

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** JavaScript prototype và inherited authorization/config flag.
- **Actor, xác thực và role:** role user gửi JSON merge/config; target vẫn là user role.
- **Điều kiện khai thác:** recursive merge nhận các khóa điều khiển prototype ở bất kỳ độ sâu nào và một gadget sau đó đọc inherited property.
- **Browser, proxy, framework và phiên bản:** Node.js 20 với merge library được pin và process mới cho mỗi case; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với prototype pollution, input đi qua recursive merge để sửa inherited property, rồi gadget tiêu thụ property đó. Positive case phải chứng minh cả hai bước; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Node.js 20 với merge library được pin và process mới cho mỗi case; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case prototype pollution; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh merge đã sửa inherited property và gadget đọc đúng marker; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của prototype pollution; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

Lỗ hổng thường xuất hiện qua 3 biến thể chính:

### 1. Server-side Prototype Pollution dẫn đến RCE
Khi ứng dụng Node.js sử dụng các hàm như `child_process.fork()`, `child_process.spawn()`, hoặc `child_process.execSync()` mà không cấu hình đầy đủ các tham số (hoặc truyền đối tượng options rỗng), Node.js sẽ kiểm tra `Object.prototype` để lấy các cấu hình mặc định nếu chúng không được định nghĩa rõ ràng. Kẻ tấn công có thể lợi dụng điều này để làm ô nhiễm các thuộc tính cấu hình hệ thống:
- **`execArgv`**: Mảng các tham số truyền cho Node.js binary. Ô nhiễm thuộc tính này thành `["--eval", "payload"]` giúp thực thi mã trực tiếp khi Node.js tạo tiến trình con qua `fork()`.
- **`NODE_OPTIONS` (thông qua `env`)**: Nếu tiến trình con được sinh ra với một đối tượng `options.env` tùy chỉnh (ví dụ: `spawn('node', [], {env: {}})`), đối tượng này sẽ kế thừa thuộc tính từ `Object.prototype`. Nếu kẻ tấn công làm ô nhiễm `Object.prototype.NODE_OPTIONS = "--require=/tmp/payload.js"`, Node.js sẽ tải và thực thi mã độc tại thời điểm tiến trình con được khởi tạo.

### 2. Client-side Prototype Pollution dẫn đến XSS (XSS Chains via innerHTML)
Trên môi trường trình duyệt, nếu kẻ tấn công ô nhiễm được `Object.prototype`, họ có thể nhắm vào các đoạn mã JavaScript của ứng dụng (DOM Gadgets) mà thực hiện gán thuộc tính vào DOM mà không kiểm tra tính hợp lệ.
Ví dụ điển hình là các đoạn mã khởi tạo phần tử HTML bằng cách lấy giá trị cấu hình:
<!-- payload-id: WEB-A08-PROTOTYPE-POLLUTION-001 -->
<!-- context: Node.js 20 with lodash.merge 4.17.11 in a disposable jsdom/Chromium fixture; config.html is inherited after a vulnerable deep merge -->
<!-- prerequisites: fresh process/browser context; synthetic span marker; no cookie, process creation or network access; delete polluted property during cleanup -->
<!-- encoding: UTF-8 JavaScript; JSON __proto__ key and marker HTML are represented in exact string bytes -->
<!-- expected-result: vulnerable div creates the marker element from inherited html; own-property safe config uses Default Content -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```javascript
const lodash = require("lodash"); // Fixture pins vulnerable 4.17.11.
const input = JSON.parse(
  '{"__proto__":{"html":"<span id=\\"prototype-lab-marker\\">LAB</span>"}}'
);
const config = {};
lodash.merge(config, input);

const div = document.createElement("div");
div.innerHTML = config.html || "Default Content";
document.body.appendChild(div);

if (!document.getElementById("prototype-lab-marker")) {
  throw new Error("fixture did not reproduce the inherited marker");
}
delete Object.prototype.html;
```
Nếu `config.html` không phải own property, JavaScript tiếp tục tra cứu trên prototype chain. Block trên chỉ tạo một phần tử marker vô hại và dọn thuộc tính ngay sau case; không đọc cookie hoặc thực thi process.

### 3. Lỗi cụ thể trong các thư viện (Library-specific)
Nhiều phiên bản cũ của các thư viện tiện ích phổ biến như `lodash` (hàm `lodash.merge`, `lodash.defaultsDeep`) hoặc `jQuery` (hàm `jQuery.extend` thực hiện deep copy) gặp lỗi khi xử lý các khóa đệ quy.
- **`lodash.merge` (các phiên bản < 4.17.12)**: Cho phép kẻ tấn công truyền một đối tượng JSON chứa khóa `__proto__` để ghi đè thuộc tính toàn cục.
- **`jQuery.extend` (các phiên bản < 3.4.0)**: Khi thực hiện gộp sâu (deep copy) với tham số đầu tiên là `true`, hàm này không kiểm tra khóa `__proto__`, cho phép ghi đè các phương thức/thuộc tính trên `Object.prototype`.

## 9. Code dễ bị lỗi và code an toàn

### Vulnerable Code Example (Server-side RCE & Client XSS Gadget)
```javascript
const child_process = require('child_process');
const lodash = require('lodash'); // Vulnerable version, e.g., 4.17.11

// 1. Vulnerable Server-side Merge causing RCE
function handleUserPreferences(userJson) {
  let preferences = {};
  // Vulnerable merge operation using outdated lodash version
  lodash.merge(preferences, JSON.parse(userJson));

  // Later in the application, a child process is forked
  // If Object.prototype.execArgv was polluted, it will be executed here
  child_process.fork('./worker.js');
}

// 2. Vulnerable Client-side Gadget (Simulated)
function renderWidget(widgetConfigJson) {
  let config = {};
  // Vulnerable merge
  lodash.merge(config, JSON.parse(widgetConfigJson));

  const container = document.createElement('div');
  // Vulnerable DOM gadget: fallback to prototype property if 'html' is undefined
  const contentHtml = config.html || "<span>Default widget content</span>";
  container.innerHTML = contentHtml; // XSS trigger
}

```

### Secure Code Example
```javascript
const child_process = require('child_process');

// Prevent any changes to the global Object prototype at the entrypoint
Object.freeze(Object.prototype);

// Safe merge function with explicit key sanitization
function safeMerge(target, source) {
  for (let key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      // Reject dangerous keys to prevent prototype pollution
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        continue;
      }

      if (target[key] !== null && typeof target[key] === 'object' &&
          source[key] !== null && typeof source[key] === 'object') {
        safeMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  return target;
}

// Safe usage of child process execution by freezing prototype and isolating env
function runSafeWorker() {
  const options = {
    // Explicitly define execArgv to override any potential polluted property
    execArgv: [],
    // Provide a fresh environment object or filter env properties
    env: Object.assign(Object.create(null), process.env)
  };
  child_process.fork('./worker.js', [], options);
}

// Safe client-side rendering using sanitization and clean objects
function renderSafeWidget(widgetConfigJson) {
  // Use a clean map without prototype
  const config = Object.create(null);
  const parsed = JSON.parse(widgetConfigJson);

  // Sanitized merge
  safeMerge(config, parsed);

  const container = document.createElement('div');
  // Safe default lookup (doesn't inherit from Object.prototype)
  const contentHtml = config.html || "<span>Default widget content</span>";

  // In real applications, sanitization (e.g. DOMPurify) should be used before innerHTML
  container.textContent = contentHtml; // Safer alternative to innerHTML
}
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến Prototype Pollution, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Từ chối mọi khóa điều khiển prototype ở mọi độ sâu, dùng merge an toàn và authorize bằng own server field. [S1]
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với Prototype Pollution, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Ngăn chặn Prototype Pollution bằng cách đóng băng nguyên mẫu Object.prototype, sử dụng các object không có prototype, và cập nhật các thư viện an toàn.
- **Các bước chi tiết**:
  - **Đóng băng nguyên mẫu (Prototype Freezing)**: Gọi `Object.freeze(Object.prototype)` ở đầu ứng dụng để ngăn chặn mọi hành vi chỉnh sửa thuộc tính của đối tượng cơ sở.
  - **Sử dụng đối tượng không có Prototype**: Khởi tạo các đối tượng lưu trữ dữ liệu dạng key-value bằng `Object.create(null)` để loại bỏ hoàn toàn liên kết nguyên mẫu, ngăn ngừa các cơ chế tra cứu chuỗi prototype.
  - **Sử dụng thư viện an toàn và pin phiên bản**: Nâng cấp dependency đã vá theo advisory của chính dependency, pin lockfile và vẫn kiểm tra khóa ở trust boundary; một version floor không thay thế review gadget. [S1]
  - **Lọc khóa dữ liệu đầu vào**: Khi tự xây dựng hàm merge hoặc parse JSON, luôn thực hiện kiểm tra và loại bỏ các khóa nhạy cảm trước khi gộp đối tượng.

## 12. Retest

- **Positive case:** với Prototype Pollution, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của Prototype Pollution mà không xác nhận side effect và log.
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

- **Prototype Inheritance (Kế thừa nguyên mẫu)**: Cơ chế trong JavaScript cho phép các đối tượng kế thừa thuộc tính và phương thức từ một đối tượng nguyên mẫu khác để tái sử dụng mã nguồn.
- **Prototype Chain (Chuỗi nguyên mẫu)**: Chuỗi object mà JavaScript tra cứu khi property không tồn tại trực tiếp trên object hiện tại.
- **Prototype accessor**: Accessor lịch sử có thể đọc hoặc thay đổi prototype của một object; không nên được coi là khóa dữ liệu nghiệp vụ.
- **`Object.prototype`**: Đối tượng cơ sở cao nhất, đóng vai trò là "cụ tổ" của hầu như toàn bộ đối tượng trong JavaScript.
- **Merge (Gộp đối tượng)**: Hành động kết hợp các thuộc tính từ nhiều đối tượng khác nhau thành một đối tượng duy nhất.
- **XSS (Cross-Site Scripting)**: Lỗ hổng chèn mã độc JavaScript vào trang web để thực thi trên trình duyệt của nạn nhân.
- **Client-side**: Phía máy khách, đề cập đến các hoạt động và mã nguồn chạy trực tiếp trên thiết bị (trình duyệt) của người dùng.
- **DOM (Document Object Model)**: Giao diện lập trình ứng dụng dạng cây dùng để biểu diễn và tương tác với các cấu trúc tài liệu HTML/XML của trang web.
- **DOM Gadget**: Đoạn mã JavaScript hợp lệ có sẵn trên trang web nhưng có thể bị lợi dụng để kích hoạt lỗ hổng bảo mật (như XSS) khi kết hợp với đầu vào bị kiểm soát.
- **Deep Copy (Sao chép sâu)**: Sao chép một đối tượng bằng cách tạo ra các bản sao vật lý mới cho cả các đối tượng con nằm sâu bên trong nó, thay vì chỉ sao chép tham chiếu.

## 16. Bài liên quan và đọc thêm

- [Insecure Deserialization](../insecure-deserialization/) — Lỗ hổng giải tuần tự hóa không an toàn thường kết hợp với Prototype Pollution để khai thác các đối tượng trong môi trường runtime.

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/prototype-pollution — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** OWASP. https://owasp.org/www-pdf-archive/OWASP_Top_10_2021_Draft_v1.1.pdf — phiên bản/trạng thái: archived draft, không phải bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/1321.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
