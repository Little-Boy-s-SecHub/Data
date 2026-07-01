# Regex Injection

> **CWE**: CWE-1287 (Improper Validation of Specified Type of Input) | **Phân loại**: Injection

## Kiến thức Nền tảng

Biểu thức chính quy (Regex) giống như một tấm lưới lọc văn bản vô cùng thông minh giúp tìm kiếm các chuỗi ký tự theo một quy luật định sẵn. Khi lọc thông tin, các bộ máy Regex thường sử dụng cơ chế "quay lui" (backtracking) – tức là nếu thử một đường đi không khớp, nó sẽ quay lại ngã rẽ trước đó để thử đường đi khác. Tuy nhiên, nếu tấm lưới lọc này được thiết kế quá phức tạp (ví dụ chứa các vòng lặp lồng nhau) gặp đúng một chuỗi dữ liệu gần giống nhưng không khớp ở phút chót, bộ máy Regex sẽ phải thử hàng triệu triệu tổ hợp đường đi khác nhau. Hiện tượng này gọi là quay lui vô hạn (catastrophic backtracking), giống như một người bị lạc vào mê cung không lối thoát và kiệt sức vì cố tìm đường.

```javascript
// JavaScript normal operation of regex searching
function escapeRegex(inputString) {
    // Escapes special regex characters to treat them as literal characters
    return inputString.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function searchUserContent(userInput, documentText) {
    // Escape the user input to prevent regex injection / catastrophic backtracking
    const safePattern = escapeRegex(userInput);
    
    // Create a regular expression safely using the escaped literal pattern
    const regex = new RegExp(safePattern, 'i');
    return regex.test(documentText);
}
```

## Mô tả lỗ hổng

Lỗ hổng Regex Injection xảy ra khi ứng dụng cho phép người dùng tự thiết kế tấm lưới lọc Regex này mà không qua bất kỳ khâu xử lý an toàn nào. Kẻ tấn công có thể chèn các ký tự đặc biệt để biến đổi tấm lưới lọc thành một mê cung siêu phức tạp, đồng thời gửi kèm một chuỗi văn bản đặc biệt để kích hoạt hiện tượng quay lui vô hạn. Khi máy chủ cố gắng xử lý yêu cầu này, CPU của nó sẽ bị quá tải hoàn toàn (đạt mức 100%), khiến toàn bộ ứng dụng bị đóng băng hoặc treo máy, không thể phục vụ bất kỳ ai khác. Cuộc tấn công này gọi là Từ chối dịch vụ bằng biểu thức chính quy (ReDoS), gây thiệt hại nghiêm trọng đến sự hoạt động liên tục của dịch vụ.

## Cơ chế tấn công

Bước 1: Kẻ tấn công tìm thấy một tính năng tìm kiếm hoặc lọc dữ liệu sử dụng biểu thức chính quy (Regex) được xây dựng động từ chuỗi tìm kiếm đầu vào của người dùng.
Bước 2: Kẻ tấn công gửi một chuỗi đầu vào được thiết kế đặc biệt chứa các nhóm lặp lồng nhau (ví dụ: `(a+)+` hoặc `(a|a)+$`) cùng với một chuỗi không khớp ở cuối (như `aaaaaaaaaaaaaaaaaaaaaaaa!`).
Bước 3: Trình phân tích Regex của máy chủ thực hiện cơ chế quay lui (backtracking) qua hàng triệu khả năng để tìm kiếm sự trùng khớp.
Bước 4: CPU của máy chủ bị đẩy lên 100% trong thời gian dài để xử lý yêu cầu duy nhất này, dẫn đến treo ứng dụng và từ chối dịch vụ (DoS) đối với các người dùng khác.

## Biện pháp phòng thủ

- **Tóm tắt**: Tiêm biểu thức chính quy (ReDoS) xảy ra khi dữ liệu đầu vào từ người dùng được dùng trực tiếp để xây dựng regex mà không qua làm sạch, hoặc khi bản thân regex có lỗi quay lui vô hạn. Biện pháp giảm thiểu bao gồm: escape dữ liệu đầu vào, dùng engine không quay lui, thiết lập timeout cho thao tác khớp mẫu, và tránh tạo regex động từ tham số người dùng.
- **Các bước chi tiết**:
  - Không tạo biểu thức chính quy động từ dữ liệu đầu vào chưa được escape.
  - Nếu bắt buộc phải tạo regex động, hãy escape toàn bộ ký tự đặc biệt của regex trước.
  - Viết biểu thức chính quy cẩn thận để tránh quay lui vô hạn (tránh các bộ định lượng lồng nhau, các lớp ký tự trùng lặp).
  - Triển khai kiểm soát timeout nghiêm ngặt cho quá trình thực thi regex, hoặc sử dụng engine an toàn (như RE2 của Google) đảm bảo độ phức tạp tuyến tính.

## Code Example

```python
# ReDoS vulnerable pattern: catastrophic backtracking on (a+)+ type
import re, time

# Vulnerable: exponential backtracking
pattern = r'^(a+)+$'  # catastrophic for input like 'aaaaaaaaaaaaaaaaaX'
test_input = 'a' * 30 + 'X'

start = time.time()
try:
    re.match(pattern, test_input, timeout=5)
except re.error:
    pass
print(f'Time: {time.time() - start:.2f}s')  # can take seconds/minutes

# Secure: use atomic groups or rewrite pattern to avoid ambiguity
# Or use timeout mechanism
def safe_match(pattern, text, timeout=1.0):
    import signal
    def handler(signum, frame): raise TimeoutError
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(int(timeout))
    try:
        return re.match(pattern, text)
    finally:
        signal.alarm(0)
```

```javascript
function escapeRegExp(string) {
  // Escape special characters so they are treated as literal characters
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Secure construction using the escaped user string
const safeRegex = new RegExp(escapeRegExp(userInput), 'i');
```

## Xem thêm

- [Command Execution](../command-execution/) — Thực thi lệnh thông qua xử lý không an toàn.

## Nguồn tham khảo

- OWASP A03:2021, CWE-1287

## Giải thích thuật ngữ

- **Regex / Regular Expression**: Biểu thức chính quy dùng để so khớp chuỗi theo mẫu.
- **Backtracking**: Cơ chế quay lại các bước trước đó trong bộ máy Regex để tìm kiếm mọi khả năng khớp.
- **ReDoS**: Cuộc tấn công từ chối dịch vụ bằng cách làm quá tải bộ máy xử lý Regex.
- **Catastrophic Backtracking**: Hiện tượng quay lui vô hạn gây tiêu tốn tài nguyên CPU ở mức tối đa.
- **Escape**: Hành động vô hiệu hóa ý nghĩa của các ký tự đặc biệt bằng cách chèn dấu gạch chéo ngược `\` phía trước.
