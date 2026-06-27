# Logging and Monitoring

> **OWASP Top 10:2025**: A09:2025 – Logging & Alerting Failures | **CWE**: CWE-778 (Insufficient Logging) | **Phân loại**: Design & Process

## 🧱 Kiến thức Nền tảng
Nhật ký bảo mật ứng dụng (application security logging) là quá trình hệ thống chủ động ghi lại các sự kiện có ảnh hưởng tới an ninh thông tin. Các sự kiện này gồm đăng nhập thành công/thất bại, truy cập bị từ chối, lỗi xác thực đầu vào, và hành động thay đổi cấu hình. Mục tiêu ghi nhật ký là tạo ra dấu vết kiểm toán (audit trail) minh bạch, giúp quản trị viên điều tra khi xảy ra sự cố bảo mật.

Để phân tích tự động hiệu quả, nhật ký cần tuân theo định dạng chuẩn hóa (event log format), như JSON. Mỗi dòng nhật ký phải chứa đầy đủ thông tin ngữ cảnh gồm nhãn thời gian (timestamp), định danh người dùng, IP nguồn, mã theo dõi (trace ID) và mô tả hành động. Đặc biệt, định dạng log phải đảm bảo không lưu giữ dữ liệu cá nhân nhạy cảm (PII) như mật khẩu, khóa API hoặc số thẻ tín dụng bằng cách che dấu (masking) hoặc ẩn danh hóa.

Luồng log sau đó được đẩy thời gian thực về hệ thống quản lý tập trung (SIEM centralized log aggregation). SIEM thu thập, lưu trữ log tại nơi an toàn chống ghi đè (tamper-resistant). Bằng cách tương quan hóa các sự kiện (correlation) từ nhiều nguồn, SIEM phát hiện sớm các chiến dịch tấn công phức tạp (như brute-force) và kích hoạt cảnh báo tức thời cho đội phản ứng sự cố.

## 💻 Code Example: Normal Structured Logging Configuration
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

## 🔍 Mô tả lỗ hổng
Thiếu sót trong ghi nhật ký và giám sát (Logging and Monitoring Failures) khiến doanh nghiệp không thể phát hiện kịp thời các hành vi bất thường hoặc các cuộc tấn công đang diễn ra. Nếu không có nhật ký chi tiết về các sự kiện quan trọng như đăng nhập thất bại hoặc thay đổi quyền hạn, quản trị viên sẽ không có bằng chứng để điều tra sự cố. Tuy nhiên, việc ghi nhật ký quá chi tiết cũng cần tránh lưu trữ các dữ liệu nhạy cảm của người dùng (PII) như mật khẩu hay số thẻ tín dụng.

## ⚔️ Cơ chế tấn công
Bước 1: Kẻ tấn công thực hiện tấn công vét cạn (brute-force) mật khẩu tài khoản của quản trị viên hệ thống bằng cách gửi hàng ngàn yêu cầu đăng nhập liên tục.
Bước 2: Do ứng dụng không ghi nhận nhật ký (log) các lần đăng nhập thất bại và không có hệ thống giám sát cảnh báo lưu lượng bất thường, hành động này diễn ra âm thầm mà không bị phát hiện.
Bước 3: Kẻ tấn công dò ra mật khẩu đúng, đăng nhập thành công và thực hiện các thay đổi cấu hình nhạy cảm mà không để lại dấu vết điều tra do thiếu cơ chế Audit Log.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Ensure sufficient security visibility by logging critical events, including diagnostic context, and using SIEM dashboards for detection.
- **Các bước chi tiết**:
  - Record all security-relevant events, including authentication attempts, access control failures, validation errors, and high-impact actions.
  - Ensure log entries include timestamps, trace IDs, user identities, and source IPs while strictly masking credentials or PII.
  - Forward log streams in real-time to a secure, centralized log aggregation or SIEM system.
  - Set up alerting thresholds for suspicious activities, such as elevated authentication failures or high-frequency API consumption.
  - Store logs on tamper-resistant storage and restrict write/read permissions to authorized systems.

## 💻 Code Example
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

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: PASS
- **Ghi chú kỹ thuật**: Trong Milestone 2, bài học này có trạng thái PASS. Đảm bảo cấu hình hệ thống ghi nhật ký đầy đủ cho các sự kiện bảo mật quan trọng (như đăng nhập thất bại, thay đổi quyền hạn) nhưng không ghi đè thông tin nhạy cảm cá nhân (PII).
- **Nguồn tham khảo**: OWASP A09:2021, CWE-778
