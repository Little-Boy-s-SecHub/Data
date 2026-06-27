# Regex Injection

> **OWASP Top 10:2025**: A05:2025 – Injection | **CWE**: CWE-1287 (Improper Validation of Specified Type of Input) | **Phân loại**: Injection

## 🧱 Kiến thức Nền tảng
Biểu thức chính quy (Regular Expression - Regex) là công cụ mạnh mẽ dùng để mô tả các mẫu tìm kiếm chuỗi văn bản bằng cú pháp đặc biệt. Cú pháp này bao gồm các ký tự chữ và số thông thường cùng với các ký tự đặc biệt (meta-characters) như `.`, `*`, `+`, `?`, `^`, `$`, `()`, `[]`, `{}`, `\` để chỉ định các nhóm, lớp ký tự, neo ranh giới, và các bộ định lượng (quantifiers) như `*` (lặp từ 0 lần trở lên) hay `+` (lặp từ 1 lần trở lên). Khi thực hiện tìm kiếm, hầu hết các trình phân tích Regex (Regex engines) truyền thống sử dụng thuật toán NFA (Nondeterministic Finite Automaton). Thuật toán này dựa vào cơ chế quay lui (backtracking) khi gặp các ký tự không khớp trong chuỗi mục tiêu nhằm thử nghiệm mọi khả năng so khớp có thể có.

Hiện tượng quay lui vô hạn (catastrophic backtracking) xảy ra khi Regex chứa các bộ định lượng lồng nhau (ví dụ: `(a+)+`) hoặc trùng lặp, kết hợp với một chuỗi đầu vào gần khớp nhưng không khớp hoàn toàn ở cuối. Trình phân tích sẽ phải thử nghiệm một số lượng tổ hợp khả năng tăng theo hàm mũ để xác minh tính không khớp, làm cạn kiệt tài nguyên CPU của máy chủ và gây ra lỗi Từ chối dịch vụ biểu thức chính quy (ReDoS). Lỗ hổng Regex Injection xảy ra khi ứng dụng cho phép người dùng nhập trực tiếp một mẫu Regex mà không được làm sạch hoặc giới hạn. Để bảo vệ hệ thống, lập trình viên cần escape tất cả các ký tự đặc biệt của Regex trước khi đưa vào hàm biên dịch động, thiết lập thời gian chờ (timeout) cho các thao tác so khớp, hoặc sử dụng các công cụ phân tích không quay lui (như thư viện RE2 của Google) hoạt động trong thời gian tuyến tính.

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

## 🔍 Mô tả lỗ hổng
Tiêm biểu thức chính quy (Regex Injection) xảy ra khi ứng dụng sử dụng dữ liệu do người dùng nhập để xây dựng biểu thức chính quy một cách động mà không làm sạch. Kẻ tấn công có thể nhập các chuỗi ký tự đặc biệt làm thay đổi cấu trúc của Regex, gây ra hiện tượng quay lui vô hạn (catastrophic backtracking). Điều này dẫn tới tấn công Từ chối dịch vụ biểu thức chính quy (ReDoS), làm cạn kiệt tài nguyên CPU của máy chủ và khiến ứng dụng bị treo.

## ⚔️ Cơ chế tấn công
Bước 1: Kẻ tấn công tìm thấy một tính năng tìm kiếm hoặc lọc dữ liệu sử dụng biểu thức chính quy (Regex) được xây dựng động từ chuỗi tìm kiếm đầu vào của người dùng.
Bước 2: Kẻ tấn công gửi một chuỗi đầu vào được thiết kế đặc biệt chứa các nhóm lặp lồng nhau (ví dụ: `(a+)+` hoặc `(a|a)+$`) cùng với một chuỗi không khớp ở cuối (như `aaaaaaaaaaaaaaaaaaaaaaaa!`).
Bước 3: Trình phân tích Regex của máy chủ thực hiện cơ chế quay lui (backtracking) qua hàng triệu khả năng để tìm kiếm sự trùng khớp.
Bước 4: CPU của máy chủ bị đẩy lên 100% trong thời gian dài để xử lý yêu cầu duy nhất này, dẫn đến treo ứng dụng và từ chối dịch vụ (DoS) đối với các người dùng khác.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Regular Expression Injection (ReDoS) occurs when user-supplied input is dynamically used to construct a regex without sanitization or when the regex has catastrophic backtracking issues. Mitigation involves escaping user input, using non-backtracking engines, setting matching timeouts, and avoiding dynamic regex generation from user parameters.
- **Các bước chi tiết**:
  - Avoid dynamically creating regular expressions using unescaped user-supplied inputs.
  - Escape all special regex characters if dynamic construction is absolutely necessary.
  - Write regular expressions carefully to avoid catastrophic backtracking (nested quantifiers, overlapping character classes).
  - Implement strict timeout controls on regex execution, or use safe regular expression engines (like Google's RE2) which guarantee linear-time execution.

## 💻 Code Example
```javascript
function escapeRegExp(string) {
  // Escape special characters so they are treated as literal characters
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Secure construction using the escaped user string
const safeRegex = new RegExp(escapeRegExp(userInput), 'i');
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Trong Milestone 2, bài học này đã được chỉnh sửa (FIXED). Đã sửa lỗi Flask route format mismatch ở Slide 2. Sửa lỗi cú pháp RegExp escaping trong JavaScript: thay thế /[.*+?^${}()|[\\\\]\\\\]/g bằng biểu thức chuẩn an toàn /[.*+?^${}()|[\]\\]/g để tránh lỗi cú pháp và đảm bảo escape đầy đủ.
- **Nguồn tham khảo**: OWASP A03:2021, CWE-1287
