---
schema_version: 1
id: WEB-A09-LOGGING-AND-MONITORING
title: "Logging and Monitoring"
slug: logging-and-monitoring
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A09:2025
cwe:
  - CWE-778
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Logging and Monitoring

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Logging and Monitoring bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng một ngân hàng hoạt động mà hoàn toàn không có camera giám sát và bảo vệ ghi chép nhật ký ra vào. Khi có kẻ trộm đột nhập cuỗm đi két sắt, người quản lý chỉ biết đứng nhìn đống đổ nát mà không có bất kỳ manh mối nào để truy vết. Trong thế giới phần mềm, **nhật ký bảo mật (Logging)** đóng vai trò chính là hệ thống camera an ninh hoạt động 24/7 đó. Nhiệm vụ của nó là ghi nhận lại mọi biến động quan trọng: từ những lần đăng nhập thành công hay thất bại, hành vi cố tình đi vào khu vực cấm, cho đến những thay đổi cài đặt của hệ thống. Đây chính là vết tích để lại (audit trail) giúp quản trị viên có thể dựng lại hiện trường cuộc tấn công và sửa chữa lỗ hổng kịp thời.

Tuy nhiên, camera giám sát phải ghi lại hình ảnh sắc nét và có trật tự thì mới có giá trị. Nhật ký ứng dụng cần được ghi dưới dạng cấu trúc chuẩn (như định dạng JSON) để máy tính dễ dàng đọc hiểu. Mỗi bức ảnh (dòng log) phải hiển thị rõ: thời gian chụp (timestamp), ai là người hành động (user ID), từ đâu đến (ip_address), hành động cụ thể là gì, và mã định danh giao dịch (trace ID). Thế nhưng, camera không được phép ghi lại những thông tin quá nhạy cảm riêng tư như mật khẩu, số tài khoản hay mã PIN (dữ liệu PII) để tránh việc chính camera lại trở thành nơi rò rỉ thông tin.

Cuối cùng, tất cả dữ liệu từ các camera khác nhau sẽ được truyền trực tiếp về một căn phòng trung tâm giám sát an ninh (SIEM). Tại đây, hệ thống không chỉ lưu giữ băng ghi hình ở một nơi an toàn (chống sửa xóa - tamper-resistant) mà còn tự động kết nối dữ liệu lại với nhau (correlation). Ví dụ, nếu phát hiện một vị khách gõ cửa 100 lần liên tiếp thất bại tại các chi nhánh khác nhau trong vòng 1 phút, hệ thống sẽ lập tức rung chuông báo động (alerting) cho đội phản ứng sự cố ngăn chặn ngay hành vi brute-force.

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Logging and Monitoring Failures (Lỗi thiếu sót trong ghi nhật ký và giám sát)** giống như việc hệ thống camera an ninh bị tắt hoặc hoạt động chập chờn. Khi đó, kẻ tấn công có thể ung dung đi lại, phá phách hệ thống mà không ai hay biết.

Sự nguy hiểm nằm ở chỗ:
- Khi cuộc tấn công đang diễn ra (như có kẻ đang rà quét mật khẩu), quản trị viên hoàn toàn mù tịt vì không có tín hiệu cảnh báo nào được đưa ra.
- Sau khi cuộc tấn công đã hoàn thành, máy chủ bị phá hoại hoặc mất dữ liệu, doanh nghiệp cũng chịu chết không thể biết kẻ gian đã vào bằng cách nào, đã lấy đi những gì, do không có nhật ký kiểm tra (audit log) ghi lại hành trình đó.
- Ngược lại, nếu cấu hình ghi nhật ký cẩu thả, vô tình lưu lại cả mật khẩu rõ hay thông tin thẻ tín dụng của người dùng (PII), thì đây lại trở thành "kho báu" dâng tận tay cho kẻ tấn công nếu chúng chiếm được file log.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** bản ghi đăng nhập, thay đổi quyền, thao tác quản trị; tính toàn vẹn/retention của log; và tuyến cảnh báo đến người trực.
- **Trust boundary:** sự kiện từ ứng dụng đi qua structured logger, collector và kho log/SIEM.
- **Actor:** người dùng lab tạo lần đăng nhập thành công/thất bại; quản trị viên giả lập thay đổi quyền; operator chỉ sửa bản sao log tạm thời.
- **Điều kiện cần:** sự kiện nhạy cảm không được ghi, thiếu actor/action/outcome/correlation ID, input chứa CR/LF được ghi nguyên văn, hoặc log có thể bị sửa/xóa mà không phát hiện.
- **Điều kiện môi trường:** fixture Python 3.12 và collector local; đồng hồ đồng bộ; log/alert ghi vào thư mục tạm, không gửi dữ liệu ra ngoài.

Chỉ kết luận có failure khi một sự kiện bảo mật bị mất/ngụy tạo, log mất tính toàn vẹn, hoặc cảnh báo không được tạo/chuyển đến đúng tuyến trong fixture. [S1]

## 6. Cơ chế tấn công

Input chứa CR/LF có thể tạo dòng log giả nếu logger nối chuỗi trực tiếp; một thao tác đổi quyền có thể không để lại audit event nếu code path bỏ qua logger; và quyền ghi quá rộng có thể cho phép sửa bằng chứng. Kiểm thử phải nối cùng correlation ID từ request đến application log, collector và alert để phân biệt lỗi ghi nhận với lỗi truy vấn dashboard. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy ứng dụng Python 3.12 và collector local; nạp tài khoản giả, bật structured log và ghi log vào thư mục tạm.
2. **Input:** tạo baseline gồm một đăng nhập đúng, một đăng nhập sai và một thay đổi quyền, mỗi request có correlation ID riêng.
3. **Thao tác:** lặp lại với username chứa CR/LF; tắt riêng audit hook của fixture; sửa một bản sao log bằng tài khoản không đặc quyền.
4. **Expected result:** bản dễ lỗi có dòng giả hoặc thiếu event/alert; bản sửa phải encode CR/LF, giữ đủ actor/action/outcome, từ chối sửa log và phát cảnh báo kiểm thử.
5. **Cleanup:** dừng collector, xóa tài khoản/dữ liệu/log tạm và xác nhận không còn process nền.
6. **Giới hạn an toàn:** không thao tác log hệ thống thật, không gửi sự kiện đến SIEM ngoài lab và chỉ mô phỏng tampering trên bản sao disposable.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Bước 1: Kẻ tấn công thực hiện tấn công vét cạn (brute-force) mật khẩu tài khoản của quản trị viên hệ thống bằng cách gửi hàng ngàn yêu cầu đăng nhập liên tục.
Bước 2: Do ứng dụng không ghi nhận nhật ký (log) các lần đăng nhập thất bại và không có hệ thống giám sát cảnh báo lưu lượng bất thường, hành động này diễn ra âm thầm mà không bị phát hiện.
Bước 3: Kẻ tấn công dò ra mật khẩu đúng, đăng nhập thành công và thực hiện các thay đổi cấu hình nhạy cảm mà không để lại dấu vết điều tra do thiếu cơ chế Audit Log.

### Mô phỏng sửa bản sao log trong fixture:
<!-- payload-id: WEB-A09-LOGGING-AND-MONITORING-001 -->
<!-- context: POSIX shell; chỉ thao tác trên bản sao log trong thư mục tạm của fixture local -->
<!-- prerequisites: mktemp, grep và diff; không dùng log hệ thống thật -->
<!-- encoding: UTF-8; mỗi bản ghi kết thúc bằng LF -->
<!-- expected-result: altered.log không còn dòng chứa 192.0.2.10, original.log vẫn nguyên vẹn và diff ghi nhận thay đổi -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```bash
# Create a disposable log fixture; never edit a system log for this exercise
lab_dir="$(mktemp -d)"
printf '%s\n' \
  '2026-07-17T03:42:17Z ip=192.0.2.10 action=upload result=success' \
  '2026-07-17T03:43:10Z ip=192.0.2.20 action=login result=failure' \
  > "$lab_dir/original.log"

# Simulate tampering by writing a filtered copy, preserving the original evidence
grep -v 'ip=192.0.2.10' "$lab_dir/original.log" > "$lab_dir/altered.log"
diff -u "$lab_dir/original.log" "$lab_dir/altered.log" || true

# Cleanup after collecting the expected diff in the lab report
rm -r "$lab_dir"
```

### Ví dụ phân biệt log tốt và log tồi:
<!-- payload-id: WEB-A09-LOGGING-AND-MONITORING-002 -->
<!-- context: log text; minh họa trường tối thiểu cho sự kiện xác thực trong fixture -->
<!-- prerequisites: dữ liệu định danh phải là dữ liệu giả; không ghi password, token hoặc session ID -->
<!-- encoding: UTF-8; timestamp RFC 3339 ở UTC -->
<!-- expected-result: bản ghi tốt có timestamp, actor, source, action, result, reason và correlation ID để điều tra -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# POOR: the event lacks the context needed for an investigation
[INFO] Login failed

# BETTER: structured fields support correlation without recording secrets
timestamp=2026-07-17T03:42:17Z level=WARN actor_id=user-42
source_ip=192.0.2.10 action=login result=failure reason=invalid_credential
correlation_id=req-7f12
```

## 9. Code dễ bị lỗi và code an toàn

Hai hàm sau dùng Python 3.12 cho cùng sự kiện xác thực. Bản dễ lỗi bỏ qua thất bại và nối dữ liệu không tin cậy vào text tự do; bản an toàn ghi cùng schema cho cả hai outcome, để JSON encoder xử lý ký tự điều khiển và dùng correlation ID. Không ghi mật khẩu, token hay session ID. [S2] [S3]

### Không an toàn (vulnerable): thiếu failure event và schema

```python
def record_auth_event_vulnerable(username, is_successful):
    if is_successful:
        # Vulnerable: failures disappear and untrusted data is concatenated
        print("Login succeeded for " + username)
```

### An toàn (secure): schema cố định cho mọi outcome

```python
import json
from datetime import datetime, timezone

def record_auth_event_secure(actor_id, source_ip, is_successful, trace_id):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "authentication",
        "outcome": "success" if is_successful else "failure",
        "actor_id": str(actor_id),
        "source_ip": str(source_ip),
        "trace_id": str(trace_id),
    }
    # Secure: JSON encoding preserves event boundaries and escapes controls
    print(json.dumps(event, ensure_ascii=True, separators=(',', ':')))
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Ghi nhận sự kiện có ngữ cảnh, bảo vệ log và tạo cảnh báo có người chịu trách nhiệm xử lý.
- Ghi sự kiện theo schema allowlist, encode CR/LF, chuyển log đến kho append-only có quyền tối thiểu, và kiểm thử định kỳ cả rule lẫn tuyến nhận cảnh báo.
- Dùng cùng một policy cho mọi route/operation tương đương; không chỉ sửa endpoint xuất hiện trong PoC.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Đảm bảo khả năng hiển thị bảo mật đầy đủ bằng cách ghi nhật ký các sự kiện quan trọng bao gồm thông tin chẩn đoán, và sử dụng bảng điều khiển SIEM để phát hiện.
- **Các bước chi tiết**:
  - Ghi lại tất cả các sự kiện liên quan đến bảo mật, bao gồm các lần xác thực, lỗi kiểm soát truy cập, lỗi xác thực dữ liệu và các hành động có tác động lớn.
  - Đảm bảo mỗi sự kiện có timestamp, correlation ID, actor và nguồn phù hợp với mô hình đe dọa; giảm thiểu hoặc che dữ liệu cá nhân và tuyệt đối không ghi password, khóa hay token phiên.
  - Chuyển tiếp luồng log theo thời gian thực đến hệ thống SIEM hoặc tổng hợp log tập trung an toàn.
  - Thiết lập ngưỡng cảnh báo cho các hoạt động đáng ngờ, chẳng hạn như tỷ lệ xác thực thất bại cao hoặc mức tiêu thụ API tăng bất thường.
  - Lưu trữ log trên bộ nhớ chống can thiệp (tamper-resistant) và giới hạn quyền ghi/đọc chỉ cho các hệ thống được ủy quyền.

## 12. Retest

- **Positive case:** luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Regression:** lưu testcase tối thiểu tái hiện lỗi cũ và testcase chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Đánh dấu `verified` dù nguồn, phiên bản fixture hoặc evidence payload chưa được lưu.

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

- **Audit Trail (Dấu vết kiểm toán)**: Chuỗi các ghi chép nhật ký ghi lại lịch sử hoạt động của hệ thống, giúp theo dõi hành vi và phục dựng sự cố bảo mật khi cần.
- **Log (Nhật ký)**: Bản ghi tự động các sự kiện xảy ra trong hệ thống phần mềm.
- **PII (Personally Identifiable Information - Thông tin nhận dạng cá nhân)**: Bất kỳ thông tin nào có thể dùng để định danh trực tiếp hoặc gián tiếp một cá nhân (như tên, số điện thoại, mật khẩu, thẻ tín dụng).
- **Masking (Che dấu dữ liệu)**: Kỹ thuật thay thế một phần hoặc toàn bộ ký tự nhạy cảm bằng ký tự đại diện (như dấu sao `****`) để bảo vệ thông tin.
- **SIEM (Security Information and Event Management)**: Hệ thống quản lý sự kiện và thông tin bảo mật, thu thập và phân tích log từ nhiều nguồn để phát hiện sớm mối đe dọa.
- **Tamper-resistant (Chống can thiệp)**: Khả năng ngăn chặn hoặc ghi nhận lại bất kỳ hành vi sửa đổi, xóa bỏ dữ liệu trái phép nào.
- **Correlation (Tương quan hóa)**: Quá trình liên kết các sự kiện log rời rạc từ các nguồn khác nhau để tìm ra mối liên hệ logic của một cuộc tấn công.
- **Brute-force (Tấn công vét cạn)**: Kỹ thuật thử tất cả các khả năng (như mật khẩu) để tìm ra kết quả đúng.
- **Trace ID**: Một chuỗi mã duy nhất được gán cho một yêu cầu để theo dõi hành trình của yêu cầu đó qua nhiều hệ thống dịch vụ khác nhau.

## 16. Bài liên quan và đọc thêm

- [Broken Function Level Authorization (BFLA)](../../01-broken-access-control/bfla/) — Xem thêm bài học về Broken Function Level Authorization (BFLA).

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-778. https://cwe.mitre.org/data/definitions/778.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** OWASP Logging Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
