# Logging and Monitoring

> **CWE**: CWE-778 (Insufficient Logging) | **Phân loại**: Logging & Monitoring

## Kiến thức Nền tảng
Hãy tưởng tượng một ngân hàng hoạt động mà hoàn toàn không có camera giám sát và bảo vệ ghi chép nhật ký ra vào. Khi có kẻ trộm đột nhập cuỗm đi két sắt, người quản lý chỉ biết đứng nhìn đống đổ nát mà không có bất kỳ manh mối nào để truy vết. Trong thế giới phần mềm, **nhật ký bảo mật (Logging)** đóng vai trò chính là hệ thống camera an ninh hoạt động 24/7 đó. Nhiệm vụ của nó là ghi nhận lại mọi biến động quan trọng: từ những lần đăng nhập thành công hay thất bại, hành vi cố tình đi vào khu vực cấm, cho đến những thay đổi cài đặt của hệ thống. Đây chính là vết tích để lại (audit trail) giúp quản trị viên có thể dựng lại hiện trường cuộc tấn công và sửa chữa lỗ hổng kịp thời.

Tuy nhiên, camera giám sát phải ghi lại hình ảnh sắc nét và có trật tự thì mới có giá trị. Nhật ký ứng dụng cần được ghi dưới dạng cấu trúc chuẩn (như định dạng JSON) để máy tính dễ dàng đọc hiểu. Mỗi bức ảnh (dòng log) phải hiển thị rõ: thời gian chụp (timestamp), ai là người hành động (user ID), từ đâu đến (ip_address), hành động cụ thể là gì, và mã định danh giao dịch (trace ID). Thế nhưng, camera không được phép ghi lại những thông tin quá nhạy cảm riêng tư như mật khẩu, số tài khoản hay mã PIN (dữ liệu PII) để tránh việc chính camera lại trở thành nơi rò rỉ thông tin.

Cuối cùng, tất cả dữ liệu từ các camera khác nhau sẽ được truyền trực tiếp về một căn phòng trung tâm giám sát an ninh (SIEM). Tại đây, hệ thống không chỉ lưu giữ băng ghi hình ở một nơi an toàn (chống sửa xóa - tamper-resistant) mà còn tự động kết nối dữ liệu lại với nhau (correlation). Ví dụ, nếu phát hiện một vị khách gõ cửa 100 lần liên tiếp thất bại tại các chi nhánh khác nhau trong vòng 1 phút, hệ thống sẽ lập tức rung chuông báo động (alerting) cho đội phản ứng sự cố ngăn chặn ngay hành vi brute-force.

## Mô tả lỗ hổng
Lỗ hổng **Logging and Monitoring Failures (Lỗi thiếu sót trong ghi nhật ký và giám sát)** giống như việc hệ thống camera an ninh bị tắt hoặc hoạt động chập chờn. Khi đó, kẻ tấn công có thể ung dung đi lại, phá phách hệ thống mà không ai hay biết.

Sự nguy hiểm nằm ở chỗ:
- Khi cuộc tấn công đang diễn ra (như có kẻ đang rà quét mật khẩu), quản trị viên hoàn toàn mù tịt vì không có tín hiệu cảnh báo nào được đưa ra.
- Sau khi cuộc tấn công đã hoàn thành, máy chủ bị phá hoại hoặc mất dữ liệu, doanh nghiệp cũng chịu chết không thể biết kẻ gian đã vào bằng cách nào, đã lấy đi những gì, do không có nhật ký kiểm tra (audit log) ghi lại hành trình đó.
- Ngược lại, nếu cấu hình ghi nhật ký cẩu thả, vô tình lưu lại cả mật khẩu rõ hay thông tin thẻ tín dụng của người dùng (PII), thì đây lại trở thành "kho báu" dâng tận tay cho kẻ tấn công nếu chúng chiếm được file log.

## Cơ chế tấn công
Bước 1: Kẻ tấn công thực hiện tấn công vét cạn (brute-force) mật khẩu tài khoản của quản trị viên hệ thống bằng cách gửi hàng ngàn yêu cầu đăng nhập liên tục.
Bước 2: Do ứng dụng không ghi nhận nhật ký (log) các lần đăng nhập thất bại và không có hệ thống giám sát cảnh báo lưu lượng bất thường, hành động này diễn ra âm thầm mà không bị phát hiện.
Bước 3: Kẻ tấn công dò ra mật khẩu đúng, đăng nhập thành công và thực hiện các thay đổi cấu hình nhạy cảm mà không để lại dấu vết điều tra do thiếu cơ chế Audit Log.

### Ví dụ attacker xóa log để xoá dấu vết:
```bash
# Bước 1: Attacker đã xâm nhập server, cần xóa dấu vết
# Xem log truy cập để biết mình đã để lại gì
cat /var/log/nginx/access.log | grep "192.168.1.100"
# OUTPUT: 2024-01-15 03:42:17 GET /admin/upload 200 - attacker_IP

# Bước 2: Xóa các dòng log có chứa IP của attacker
sed -i '/192.168.1.100/d' /var/log/nginx/access.log

# Bước 3: Hậu quả — Security team không còn bằng chứng
# Không biết attacker đã truy cập lúc mấy giờ
# Không biết đã tải lên file gì
# Không thể điều tra breach

# Nếu có centralized logging (gửi log ra server khác ngay lập tức)
# Attacker không thể xóa log đã được gửi đi → còn bằng chứng
```

### Ví dụ phân biệt log tốt và log tồi:
```
# Log TỒI — thiếu context để điều tra
[INFO] Login failed        ← thiếu: ai login? IP? lúc mấy giờ?
[INFO] File deleted        ← thiếu: file nào? ai xóa? từ đâu?
[ERROR] Database error     ← thiếu: query nào? user nào? lỗi gì?

# Log TỐT — đủ 5W1H để điều tra
[WARN] 2024-01-15T03:42:17Z user=john@company.com ip=1.2.3.4
       action=login_failed reason=wrong_password attempt=5/5
       → Phát hiện brute force, trigger alert
```

## Biện pháp phòng thủ
- **Tóm tắt**: Đảm bảo khả năng hiển thị bảo mật đầy đủ bằng cách ghi nhật ký các sự kiện quan trọng bao gồm thông tin chẩn đoán, và sử dụng bảng điều khiển SIEM để phát hiện.
- **Các bước chi tiết**:
  - Ghi lại tất cả các sự kiện liên quan đến bảo mật, bao gồm các lần xác thực, lỗi kiểm soát truy cập, lỗi xác thực dữ liệu và các hành động có tác động lớn.
  - Đảm bảo mỗi dòng log chứa timestamp, trace ID, thông tin nhận dạng người dùng và IP nguồn trong khi che giấu nghiêm ngặt thông tin xác thực hoặc dữ liệu PII.
  - Chuyển tiếp luồng log theo thời gian thực đến hệ thống SIEM hoặc tổng hợp log tập trung an toàn.
  - Thiết lập ngưỡng cảnh báo cho các hoạt động đáng ngờ, chẳng hạn như tỏ lệ xác thực thất bại cao hoặc mức tiêu thụ API tần suất cao.
  - Lưu trữ log trên bộ nhớ chống can thiệp (tamper-resistant) và giới hạn quyền ghi/đọc chỉ cho các hệ thống được ủy quyền.

## Code Example
### Normal Structured Logging Configuration

```python
import json
import uuid
from datetime import datetime, timezone

def generate_normal_log(user_id, ip_address, action_message):
    # Construct a structured log entry representing a normal, safe application event
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": "INFO",
        "trace_id": str(uuid.uuid4()),
        "user_id": user_id,
        "ip_address": ip_address,
        "event": "user_action",
        "message": action_message
    }
    
    # Print the structured log to stdout (ideal for containerized environments to aggregate logs)
    print(json.dumps(log_entry))

# Example usage: Logging a normal, authorized dashboard access event
generate_normal_log(user_id="usr_88291", ip_address="192.168.1.50", action_message="User successfully loaded dashboard")
```


### Safe Structured Logging Configuration

```python
import logging
import sys

# Configure structured, centralized log exporter
sec_logger = logging.getLogger('security_audit')
sec_logger.setLevel(logging.INFO)

log_format = logging.Formatter(
    '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - SECURITY_AUDIT - %(message)s'
)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(log_format)
sec_logger.addHandler(stdout_handler)

def sanitize_log_input(value):
    # Sanitize inputs to neutralize carriage return and newline characters
    return str(value).replace('\n', '_').replace('\r', '_')

def record_auth_event(username, src_ip, is_successful):
    safe_username = sanitize_log_input(username)
    safe_ip = sanitize_log_input(src_ip)
    if is_successful:
        # Log successful auth events
        sec_logger.info(f"Successful authentication for user: {safe_username} from IP: {safe_ip}")
    else:
        # Warning log for failed attempts, useful for brute force analysis
        sec_logger.warning(f"Failed authentication attempt for user: {safe_username} from IP: {safe_ip}")
```


## Xem thêm
- [Broken Function Level Authorization (BFLA)](../../01-broken-access-control/bfla/) — Xem thêm bài học về Broken Function Level Authorization (BFLA).

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A09:2021, CWE-778

## Giải thích thuật ngữ
- **Audit Trail (Dấu vết kiểm toán)**: Chuỗi các ghi chép nhật ký ghi lại lịch sử hoạt động của hệ thống, giúp theo dõi hành vi và phục dựng sự cố bảo mật khi cần.
- **Log (Nhật ký)**: Bản ghi tự động các sự kiện xảy ra trong hệ thống phần mềm.
- **PII (Personally Identifiable Information - Thông tin nhận dạng cá nhân)**: Bất kỳ thông tin nào có thể dùng để định danh trực tiếp hoặc gián tiếp một cá nhân (như tên, số điện thoại, mật khẩu, thẻ tín dụng).
- **Masking (Che dấu dữ liệu)**: Kỹ thuật thay thế một phần hoặc toàn bộ ký tự nhạy cảm bằng ký tự đại diện (như dấu sao `****`) để bảo vệ thông tin.
- **SIEM (Security Information and Event Management)**: Hệ thống quản lý sự kiện và thông tin bảo mật, thu thập và phân tích log từ nhiều nguồn để phát hiện sớm mối đe dọa.
- **Tamper-resistant (Chống can thiệp)**: Khả năng ngăn chặn hoặc ghi nhận lại bất kỳ hành vi sửa đổi, xóa bỏ dữ liệu trái phép nào.
- **Correlation (Tương quan hóa)**: Quá trình liên kết các sự kiện log rời rạc từ các nguồn khác nhau để tìm ra mối liên hệ logic của một cuộc tấn công.
- **Brute-force (Tấn công vét cạn)**: Kỹ thuật thử tất cả các khả năng (như mật khẩu) để tìm ra kết quả đúng.
- **Trace ID**: Một chuỗi mã duy nhất được gán cho một yêu cầu để theo dõi hành trình của yêu cầu đó qua nhiều hệ thống dịch vụ khác nhau.
