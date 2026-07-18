---
schema_version: 1
id: WEB-A05-COMMAND-EXECUTION
title: "Command Execution"
slug: command-execution
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-78
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Command Execution

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Command Execution bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Hiểu khác biệt giữa executable, mảng `argv` và chuỗi được POSIX shell diễn giải.
- Đọc được `subprocess.run`, `os.system`, `child_process.exec` và `execFile` trong ví dụ.
- Biết parse IPv4/IPv6 bằng thư viện kiểu dữ liệu thay vì kiểm tra hình dạng bằng regex.
- Có container non-root trên loopback, outbound network bị tắt và quan sát được cây tiến trình.

## 3. Kiến thức nền tảng

Shell diễn giải metacharacter, phép nối và mở rộng theo cú pháp riêng của shell. Khi ứng dụng chỉ cần chạy một executable cố định, API truyền mảng `argv` trực tiếp với `shell=False` tránh bước diễn giải chuỗi bởi shell; ứng dụng vẫn phải allowlist giá trị và semantics của từng đối số. [S2] [S3]

```python
import subprocess

def check_network_connectivity(host_ip):
    # Safe subprocess spawning (normal operation)
    # By passing arguments as a list and setting shell=False (default),
    # the operating system executes the 'ping' binary directly.
    # Any shell metacharacters in host_ip are treated as literal arguments, not command symbols.
    command = ["ping", "-c", "1", host_ip]
    result = subprocess.run(command, capture_output=True, text=True, shell=False)
    return result.stdout
```

## 4. Mô tả và nguyên nhân gốc

OS Command Injection xảy ra khi input không tin cậy làm thay đổi cấu trúc lệnh mà ứng dụng chuyển tới shell hoặc command interpreter. Bài chỉ dùng marker trên stdout của container disposable; không ghi file hệ thống, không mở callback và không suy rộng kết quả giữa POSIX shell, `cmd.exe` và PowerShell. [S1] [S2] [S3]

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** quyền của tiến trình non-root, filesystem và biến môi trường.

- **Actor, xác thực và role:** người dùng public hoặc role user gọi chức năng ping/convert; không có shell account.

- **Điều kiện khai thác:** input đổi cấu trúc chuỗi đưa vào shell hoặc command interpreter. [S1] [S2] [S3]

- **Runtime:** fixture pin Python 3.12 và POSIX `sh` trong container non-root; không suy rộng sang PowerShell hay `cmd.exe`.

- **Evidence:** lưu host đã decode, API tạo process và stdout; marker phải là output của lệnh thứ hai.

## 6. Cơ chế tấn công

Trong bản dễ lỗi, dấu chấm phẩy kết thúc đối số của `ping` và yêu cầu POSIX shell chạy thêm `printf`. Bản sửa parse host thành địa chỉ IP, gọi executable cố định bằng mảng `argv` và không khởi tạo shell, nên cùng chuỗi phải bị từ chối trước khi tạo tiến trình. [S1] [S2]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Python 3.12/Flask 3.x trong container POSIX non-root với shell được pin; HTTP/1.1 loopback; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case command execution; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “input bị nối vào chuỗi shell hoặc truyền với shell=True”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của command execution; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Probe dưới đây vẫn ở `static-verified`: chỉ cú pháp POSIX `sh`, context và annotation đã được rà; chưa có runtime evidence. [S1] [S2]

Time-based, OOB, wildcard và newline phụ thuộc shell/OS; probe này không xác nhận các biến thể đó. [S1] [S2]

<!-- claim-source: [S1] [S2] -->
<!-- payload-id: WEB-A05-COMMAND-EXECUTION-001 -->
<!-- context: POSIX sh fixture concatenates the decoded host value into a shell command -->
<!-- prerequisites: disposable loopback container; outbound network disabled; stdout captured; one request -->
<!-- encoding: UTF-8 form value percent-encoded once; the shell receives one semicolon and an ASCII marker -->
<!-- expected-result: vulnerable fixture prints COMMAND_INJECTION_LAB after its normal output; argv-based secure fixture treats the full value as data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-18 -->
```text
127.0.0.1; printf COMMAND_INJECTION_LAB
```

## 9. Code dễ bị lỗi và code an toàn

```python
# === VULNERABLE CODE (Python) ===
import os

def check_ip_vulnerable(user_input):
    # DANGER: Directly concatenating input into os.system executes it via shell
    # Input like "127.0.0.1; sleep 5" will trigger time-based injection
    command = f"ping -c 1 {user_input}"
    os.system(command)

# === SECURE CODE (Python) ===
import subprocess
import ipaddress

def check_ip_secure(user_input):
    # Parse and canonicalize a real IPv4/IPv6 address
    host = str(ipaddress.ip_address(user_input))

    # Run the fixed executable directly without a shell
    subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True)
```

```javascript
// === VULNERABLE CODE (Node.js) ===
const { exec } = require('child_process');

function pingVulnerable(ip) {
  // DANGER: exec invokes a shell, allowing metacharacter exploitation
  exec(`ping -c 1 ${ip}`, (err, stdout) => {
    console.log(stdout);
  });
}

// === SECURE CODE (Node.js) ===
const { execFile } = require('child_process');
const { isIP } = require('net');

function pingSecure(ip) {
  if (isIP(ip) === 0) {
    throw new TypeError('Expected an IPv4 or IPv6 address');
  }
  // Run a fixed executable directly without invoking a shell
  execFile('ping', ['-c', '1', ip], (err, stdout) => {
    console.log(stdout);
  });
}
```

## 10. Phát hiện

- Tìm `os.system`, `shell=True`, `child_process.exec` và chuỗi lệnh ghép từ request hoặc dữ liệu lưu trữ.

- Ghi executable, đối số canonical, exit code và thời lượng; không ghi environment hay command line có secret.

- So cây process với allowlist; shell phát sinh dưới web worker là tín hiệu điều tra.

- Marker phải đến từ stdout của `printf`; lỗi hoặc độ trễ của `ping` không chứng minh command injection.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Không gọi shell khi không cần; dùng executable cố định và argv được allowlist.

- Parse IPv4/IPv6 bằng thư viện kiểu dữ liệu và từ chối input sai trước khi tạo tiến trình. [S2]

### Defense-in-depth

- Chạy worker không đặc quyền, filesystem chỉ đọc và không cấp outbound network nếu chỉ ping loopback. [S2] [S3]

- Đặt timeout, giới hạn số process và cố định đường dẫn executable. [S2]

- Giám sát cây tiến trình và shell không mong đợi. Các biện pháp này giảm tác động nhưng không làm cho chuỗi lệnh ghép bằng input trở nên an toàn. [S2] [S3]

## 12. Retest

- **Positive case:** `127.0.0.1` và `::1` được parser chấp nhận, rồi `ping` chạy bằng đúng executable và mảng đối số dự kiến.
- **Negative case:** `127.0.0.1; printf COMMAND_INJECTION_LAB` bị từ chối và cây tiến trình không xuất hiện shell hay `printf`.
- **Boundary case:** thử khoảng trắng đầu/cuối, IPv4 có octet sai, IPv6 nén, dấu xuống dòng đã decode và ký tự shell của đúng hệ điều hành fixture.
- **Telemetry:** xác nhận log ghi host canonical, exit code và executable nhưng không ghi secret; số tiến trình khớp đúng một lần gọi.
- **Regression:** kiểm tra cả endpoint HTTP lẫn helper tạo tiến trình để phát hiện route nào còn dùng `shell=True` hoặc `exec`.

## 13. Sai lầm thường gặp

- Chặn vài ký tự như `;` và `&` nhưng vẫn chuyển chuỗi vào shell; quoting và expansion khác nhau theo shell.

- Dùng regex IPv4 chỉ kiểm tra hình dạng, nên vẫn chấp nhận octet ngoài phạm vi hoặc biểu diễn không mong muốn.

- Chuyển từ `exec` sang `spawn` nhưng vẫn bật tùy chọn shell hoặc cho người dùng kiểm soát tên executable.

- Chạy payload POSIX trên PowerShell hoặc `cmd.exe` rồi kết luận ứng dụng an toàn khi marker không xuất hiện.

- Dùng timeout hay tài khoản ít quyền như bản sửa chính; chúng chỉ giới hạn tác động sau khi injection đã xảy ra.

## 14. Tóm tắt và checklist

- [ ] Đã xác định shell cụ thể, API tạo tiến trình và quyền của web worker.
- [ ] Probe chỉ in marker lên stdout, không ghi file, gọi callback hay tạo độ trễ dài.
- [ ] Bản sửa dùng executable cố định, `shell=False`/`execFile` và đối số đã parse.
- [ ] Test xác nhận không có shell hoặc tiến trình thứ hai trong cây process.
- [ ] IPv4, IPv6 và input sai biên đều có expected result rõ ràng.
- [ ] Giới hạn tiến trình, timeout và quyền thấp chỉ được ghi là defense-in-depth.

## 15. Giải thích thuật ngữ

- **Command Execution**: Lỗ hổng thực thi lệnh hệ điều hành trái phép do người dùng chèn vào.
- **OS Shell**: Giao diện dòng lệnh giúp tương tác và điều khiển hệ điều hành.
- **Metacharacters**: Ký tự đặc biệt (như `;`, `&`, `|`) dùng để điều khiển luồng lệnh trong shell.
- **Subprocess**: Tiến trình con được sinh ra để thực hiện một tác vụ riêng biệt.
- **RCE**: Khả năng thực thi code từ một vị trí mạng; OS command injection chỉ đạt tác động này khi sink có thể được điều khiển qua luồng từ xa và quyền tiến trình cho phép. [S3]

## 16. Bài liên quan và đọc thêm

- [Code Injection](../code-injection/) — Tấn công chèn mã trực tiếp vào runtime của ngôn ngữ lập trình (như eval) thay vì gọi lệnh hệ điều hành.
- [File Upload](../../06-insecure-design/file-upload/) — Tải lên tệp tin độc hại (web shell) để đạt được thực thi lệnh từ xa trên máy chủ.
- [Remote Code Execution](../../10-exceptional-conditions/remote-code-execution/) — Khái niệm thực thi mã từ xa trên máy chủ đích thông qua nhiều vector tấn công khác nhau.

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/os-command-injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** OWASP. https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/78.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
