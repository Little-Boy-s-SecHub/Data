---
schema_version: 1
id: WEB-A10-BUFFER-OVERFLOWS
title: "Buffer Overflows"
slug: buffer-overflows
level: advanced
estimated_minutes: 65
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp: []
cwe:
  - CWE-120
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Buffer Overflows

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Buffer Overflows bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bộ nhớ máy tính giống như một dãy các ngăn tủ lưu trữ liên tiếp. Khi chạy chương trình, máy tính chia các ngăn tủ này thành hai khu vực quản lý khác nhau:
- **Stack (Ngăn xếp)**: Giống như một chiếc hộp hẹp đứng, nơi bạn xếp chồng tài liệu lên nhau. Tài liệu nào đặt vào sau cùng sẽ được lấy ra trước (LIFO). Nơi đây lưu trữ các biến tạm thời và đặc biệt là một tờ giấy ghi nhớ "địa chỉ quay lại" (Return Address). Khi một hàm chạy xong, chương trình sẽ đọc tờ giấy này để biết phải quay lại làm tiếp công việc gì ở bên ngoài. Vùng nhớ này chạy cực kỳ nhanh nhưng không gian rất nhỏ.
- **Heap (Vùng nhớ động)**: Giống như một nhà kho lớn linh hoạt, nơi lập trình viên phải chủ động thuê chỗ (bằng hàm `malloc`/`new`) và tự trả phòng khi dùng xong (bằng hàm `free`/`delete`). Nhà kho này rộng rãi hơn nhiều nhưng tốc độ lấy đồ sẽ chậm hơn một chút.

Trong ngôn ngữ lập trình cấp thấp như C/C++, việc cấp phát bộ đệm (**Buffer Allocation**) chỉ đơn thuần là xếp đặt một dãy các ô tủ liền kề nhau. Đáng sợ là, các ngôn ngữ này không hề có người bảo vệ đứng kiểm tra xem dữ liệu bạn nhét vào có vượt quá kích thước ô tủ hay không (thiếu bounds checking).

Nếu bạn sử dụng một con trỏ (**Pointer**) – giống như một cây bút viết địa chỉ – để ghi dữ liệu dài hơn kích thước ngăn tủ đã đặt, cây bút sẽ không tự động dừng lại ở vạch kẻ biên. Nó sẽ tiếp tục viết tràn sang các ô tủ bên cạnh, ghi đè và phá hủy toàn bộ dữ liệu cũ của hệ thống. Trên Stack, việc ghi đè này có thể trúng ngay tờ giấy ghi nhớ "địa chỉ quay lại" (EIP/RIP). Khi hàm kết thúc, CPU đọc địa chỉ giả mạo này và nhảy thẳng tới đoạn mã độc (shellcode) của kẻ tấn công thay vì quay lại làm việc bình thường.

### Minh họa hoạt động bình thường (Normal Operation)
```c
// Normal operation: Safe buffer copy using bounds validation in C
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define STACK_BUF_SIZE 16

void safe_stack_copy(const char *user_input) {
    char stack_buffer[STACK_BUF_SIZE]; // Allocate static buffer on the stack

    if (user_input == NULL) {
        return;
    }

    // Measure length of input safely
    size_t input_len = strlen(user_input);

    // Validate size before write operation to prevent stack overflow
    if (input_len < STACK_BUF_SIZE) {
        // Safe copy operation preserving boundary limits
        strncpy(stack_buffer, user_input, STACK_BUF_SIZE - 1);
        stack_buffer[STACK_BUF_SIZE - 1] = '\0'; // Guarantee null-termination
        printf("Successfully copied to stack: %s\n", stack_buffer);
    } else {
        printf("Warning: Input string is too long for the allocated stack buffer.\n");
    }
}

void safe_heap_copy(const char *user_input) {
    if (user_input == NULL) {
        return;
    }

    size_t input_len = strlen(user_input);

    // Allocate memory dynamically on the heap based on input length plus null terminator
    char *heap_buffer = (char *)malloc(input_len + 1);
    if (heap_buffer == NULL) {
        printf("Memory allocation failed.\n");
        return;
    }

    // Safe to copy as heap_buffer size precisely matches input size
    strcpy(heap_buffer, user_input);
    printf("Successfully copied to heap: %s\n", heap_buffer);

    // Always release allocated heap memory to avoid leaks
    free(heap_buffer);
}
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Buffer Overflow (Tràn bộ đệm)** giống như việc cố gắng đổ một lít nước vào một chiếc ly chỉ chứa được 200ml. Nước sẽ tràn ra bàn, làm ướt sũng các tài liệu quan trọng xung quanh.

Trong thế giới phần mềm, khi ứng dụng ghi dữ liệu vượt giới hạn cho phép vào một bộ đệm có kích thước cố định mà không kiểm tra độ dài trước, dữ liệu dư thừa sẽ tràn ra và đè lên các vùng nhớ liền kề.
Lỗ hổng này cực kỳ nguy hiểm bởi vì:
- Nó có thể lập tức làm sập ứng dụng (Crash), gây gián đoạn dịch vụ.
- Nghiêm trọng hơn, kẻ tấn công có thể chèn vào một đoạn mã máy độc hại (shellcode), rồi ghi đè địa chỉ trả về của hàm để ép CPU thực thi đoạn mã độc đó, dẫn đến chiếm quyền điều khiển hoàn toàn hệ thống từ xa.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3], [S4], [S5].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** tính toàn vẹn bộ nhớ, luồng điều khiển và dữ liệu lân cận buffer của tiến trình toy.
- **Trust boundary:** byte từ `argv`/stdin được sao chép hoặc tính độ dài trước khi ghi vào buffer C có kích thước cố định.
- **Actor:** người dùng local trong container, chỉ truyền input vào binary fixture; không có listener mạng hay shellcode callback.
- **Điều kiện cần:** đường ghi thiếu kiểm tra độ dài hoặc có integer truncation/overflow; input thực sự chạm sink; crash chỉ là bằng chứng lỗi bộ nhớ, chưa tự chứng minh chiếm luồng điều khiển.
- **Điều kiện môi trường:** Ubuntu 22.04 x86-64, GCC 11.4 và glibc 2.35; build AddressSanitizer được dùng để xác nhận out-of-bounds.

ASLR, NX, stack canary và PIE ảnh hưởng khả năng khai thác nhưng không sửa thao tác ghi ngoài biên; phải ghi rõ flags của từng build khi diễn giải kết quả. [S1]

## 6. Cơ chế tấn công

Khi số byte sao chép lớn hơn vùng đích, thao tác ghi có thể chạm vùng nhớ kế cận; kết quả quan sát được có thể là báo cáo ASan, crash hoặc thay đổi marker lân cận. Use-after-free, format string và integer overflow là root cause khác, chỉ đưa vào kết luận khi trace tương ứng chứng minh chúng. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** compile cùng source bằng GCC 11.4 với `-g -fsanitize=address -fno-omit-frame-pointer`; ghi riêng build flags của bản dễ lỗi và bản an toàn.
2. **Input:** dùng chuỗi ASCII có độ dài tối đa 256 byte; baseline nhỏ hơn kích thước buffer.
3. **Thao tác:** thử tuần tự kích thước `N-1`, `N`, `N+1` và chuỗi cyclic bị giới hạn; lưu stderr/ASan trace và exit code.
4. **Expected result:** bản dễ lỗi tạo ASan out-of-bounds ở `N+1`; bản an toàn từ chối input quá dài, luôn null-terminate và không thay đổi marker kế cận.
5. **Cleanup:** xóa binary, core dump và container disposable sau khi lưu kết quả test.
6. **Giới hạn an toàn:** không dùng shellcode, không tắt bảo vệ trên host, không mở listener; mọi process có timeout, CPU và memory cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

<!-- payload-id: WEB-A10-BUFFER-OVERFLOWS-001 -->
<!-- context: Ubuntu 22.04 x86-64, Python 3.12 and pwntools 4.12; bytes are passed only to a local toy binary built with AddressSanitizer -->
<!-- prerequisites: cap input at 128 bytes; disable outbound network/core dumps; record exact compiler flags and binary hash -->
<!-- encoding: Python bytes from pwntools cyclic generator; no text transcoding before stdin -->
<!-- expected-result: the vulnerable toy build reports a bounded out-of-bounds access; the fixed build rejects the same boundary input -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
from pwn import cyclic

probe = cyclic(128, n=4)
assert len(probe) == 128
```

Tấn công tràn bộ đệm có nhiều biến thể tùy thuộc vào phân vùng bộ nhớ (Stack, Heap) và kiểu dữ liệu bị thao túng:

1. **Stack-based Buffer Overflow (Tràn bộ đệm trên Stack)**:
   Kẻ tấn công gửi đầu vào vượt quá kích thước bộ đệm trên Stack (ví dụ qua các hàm không an toàn như `gets()`, `strcpy()`). Dữ liệu thừa ghi đè lên địa chỉ trả về (Return Address) của stack frame hiện tại. Khi hàm thực hiện lệnh `ret` (return), CPU sẽ nhảy tới địa chỉ bị ghi đè này (có thể là địa chỉ chứa shellcode trên stack được đệm bởi NOP sled hoặc địa chỉ của một hàm hệ thống).

2. **Heap Buffer Overflow (Tràn bộ đệm trên heap)**:
   Kẻ tấn công ghi dữ liệu vượt quá kích thước vùng nhớ được cấp phát động. Dữ liệu có thể làm hỏng đối tượng hoặc metadata liền kề; tác động cụ thể phụ thuộc allocator, layout và hardening của phiên bản fixture. **Use-After-Free** là một weakness riêng (CWE-416), không phải một biến thể của buffer overflow. [S3]

3. **Weakness liên quan nhưng khác loại: Format String (CWE-134)** [S4]:
   Xảy ra khi dữ liệu người dùng nhập được truyền trực tiếp làm chuỗi định dạng (format string) trong các hàm thuộc họ `printf(user_input)` thay vì `printf("%s", user_input)`.
   - **%x / %p (Leak stack)**: Kẻ tấn công gửi chuỗi chứa nhiều ký tự `%x` hoặc `%p` để đọc dữ liệu trên stack. Kỹ thuật này giúp rò rỉ các giá trị nhạy cảm như Canary, địa chỉ trả về để tính toán địa chỉ gốc của thư viện (bypass ASLR).
   - **%n (Arbitrary write)**: Ký tự đặc biệt `%n` ghi số lượng byte đã được in trước đó vào địa chỉ được trỏ bởi đối số tương ứng trên stack. Bằng cách điều khiển cấu trúc stack và số lượng ký tự in ra, kẻ tấn công có thể ghi đè một giá trị tùy ý vào một địa chỉ bộ nhớ bất kỳ (ví dụ: ghi đè địa chỉ trả về hoặc Global Offset Table - GOT).

4. **Weakness liên quan nhưng khác loại: Integer Overflow (CWE-190)** [S5]:
   Xảy ra khi một phép toán số học vượt quá giới hạn lưu trữ tối đa hoặc tối thiểu của kiểu dữ liệu số nguyên.
   - **Unsigned overflow trong C** có ngữ nghĩa modulo $2^N$ đối với kiểu rộng $N$ bit.
   - **Signed overflow trong C** là undefined behavior; không được giả định rằng giá trị luôn quay vòng sang số âm.
   Kẻ tấn công lợi dụng việc tràn số nguyên để vượt qua cơ chế kiểm tra độ dài đầu vào. Ví dụ, biểu thức kiểm tra kích thước bộ đệm `length + 1` có thể bị tràn và quay về `0` nếu `length` bằng giá trị tối đa (ví dụ: `65535` đối với `unsigned short`). Khi đó, chương trình cấp phát bộ đệm kích thước `0` byte nhưng sau đó sao chép một lượng dữ liệu khổng lồ vào, dẫn đến tràn bộ đệm heap hoặc stack.

5. **Kỹ thuật khai thác, không phải root cause: ROP (Gadgets & DEP bypass)**:
   Khi hệ điều hành kích hoạt cơ chế phòng thủ **DEP/NX** (Data Execution Prevention / No-Execute), ngăn xếp và bộ nhớ heap không được phép thực thi lệnh, kẻ tấn công không thể chạy trực tiếp shellcode được chèn vào. Để bypass DEP, kẻ tấn công sử dụng kỹ thuật **Return-Oriented Programming (ROP)**.
   - **ROP Gadgets**: Kẻ tấn công tìm các đoạn lệnh máy ngắn kết thúc bằng lệnh `ret` trong mã nguồn của chương trình hoặc các thư viện dùng chung (như libc) gọi là các "gadget".
   - **ROP Chain**: Bằng cách xếp chồng liên tục các địa chỉ của các gadget này lên ngăn xếp (stack), luồng thực thi của chương trình sẽ thực hiện tuần tự từng gadget một. Chuỗi ROP (ROP chain) này có thể thiết lập các thanh ghi chứa tham số và gọi các hàm hệ thống có sẵn (như `mprotect()` để chuyển vùng nhớ sang chế độ thực thi, hoặc gọi trực tiếp `execve("/bin/sh")`) nhằm chiếm quyền điều khiển.

## 9. Code dễ bị lỗi và code an toàn

### 1. Stack Buffer Overflow
```c
// === VULNERABLE: Direct stack copy without length verification ===
#include <stdio.h>
#include <string.h>

void vuln_stack_copy(const char *user_input) {
    char buffer[32];
    // Dangerous: strcpy does not check the boundaries of the destination buffer
    strcpy(buffer, user_input);
    printf("Buffer: %s\n", buffer);
}

// === SECURE: Safe copy with bounds limit ===
#include <stdio.h>
#include <string.h>

void secure_stack_copy(const char *user_input) {
    if (user_input == NULL) return;
    char buffer[32];
    // Safe: snprintf enforces max size and guarantees null-termination
    snprintf(buffer, sizeof(buffer), "%s", user_input);
    printf("Buffer: %s\n", buffer);
}
```

### 2. Format String Vulnerability
```c
// === VULNERABLE: Passing user input directly to print formatting ===
#include <stdio.h>

void vuln_format_string(const char *user_input) {
    // Dangerous: attacker can pass format specifiers like %p to leak memory or %n to write memory
    printf(user_input);
}

// === SECURE: Enforcing explicit format specifiers ===
#include <stdio.h>

void secure_format_string(const char *user_input) {
    // Safe: explicitly specify format specifier "%s"
    printf("%s", user_input);
}
```

### 3. Integer Overflow (Signed/Unsigned)
```c
// === VULNERABLE: Arithmetic wraparound bypasses validation checks ===
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vuln_integer_overflow(unsigned short count, const char *data) {
    // If count = 65535, count + 1 wraps around to 0
    unsigned short allocated_size = count + 1;

    // Allocates a 0-byte buffer on the heap
    char *buffer = (char *)malloc(allocated_size);
    if (buffer == NULL) return;

    // Dangerous: copies 65535 bytes of data into a 0-byte allocated buffer (Heap Overflow)
    memcpy(buffer, data, count);
    free(buffer);
}

// === SECURE: Boundary validation before calculations ===
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

void secure_integer_overflow(unsigned short count, const char *data) {
    // Safe: check for overflow before performing the addition
    if (count >= USHRT_MAX) {
        printf("Integer overflow attempt blocked!\n");
        return;
    }
    unsigned short allocated_size = count + 1;
    char *buffer = (char *)malloc(allocated_size);
    if (buffer == NULL) return;

    memcpy(buffer, data, count);
    free(buffer);
}
```

### 4. Return-Oriented Programming (ROP) Concept
```c
/*
 * === CONCEPTUAL STACK LAYOUT OF A ROP CHAIN EXPLOTATION ===
 *
 * [ Low memory addresses ]
 * +-------------------------+
 * | "A" * 40 (Padding)      |  <-- Fills the stack buffer
 * +-------------------------+
 * | Saved RBP               |  <-- Overwritten frame pointer
 * +-------------------------+
 * | Address of Gadget 1     |  <-- Overwrites Return Address (e.g., 'pop rdi; ret')
 * +-------------------------+
 * | "/bin/sh" string addr   |  <-- Argument popped into RDI register
 * +-------------------------+
 * | Address of Gadget 2     |  <-- Next Return Address (e.g., system() in libc)
 * +-------------------------+
 * | Address of exit()       |  <-- Exit stub to terminate cleanly
 * +-------------------------+
 * [ High memory addresses ]
 */
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Giới hạn tài nguyên, fail safely và xử lý mọi trạng thái ngoại lệ có thể đạt tới.
- Kiểm tra kích thước trước mọi thao tác copy, dùng checked arithmetic/API có độ dài hoặc ngôn ngữ memory-safe; compiler hardening chỉ là defense-in-depth.
- Dùng cùng một policy cho mọi route/operation tương đương; không chỉ sửa endpoint xuất hiện trong PoC.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Ngăn chặn tràn bộ đệm bằng cách sử dụng các hàm thao tác bộ nhớ an toàn, thực thi kiểm tra biên và kích hoạt các cơ chế phòng thủ ở cấp độ hệ điều hành và thời gian biên dịch.
- **Các bước chi tiết**:
  - Dùng API có giới hạn rõ ràng (như `fgets` hoặc `snprintf`) thay cho `gets`, `strcpy` hoặc `scanf` không khai báo field width phù hợp.
  - Thực thi các xác thực độ dài đầu vào nghiêm ngặt để ngăn chặn đầu vào vượt quá dung lượng bộ đệm đích.
  - Biên dịch ứng dụng với các bộ bảo vệ ngăn xếp/canary (stack protectors/canaries) và các cảnh báo trong thời gian biên dịch (ví dụ: -fstack-protector).
  - Triển khai các biện pháp bảo vệ ở cấp độ hệ điều hành như Ngẫu nhiên hóa sơ đồ bố trí không gian địa chỉ (ASLR) và Ngăn chặn thực thi dữ liệu (DEP/NX).

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

- **Stack (Ngăn xếp)**: Phân vùng bộ nhớ được quản lý tự động theo cơ chế "vào sau, ra trước" (LIFO), chuyên dùng để lưu trữ biến cục bộ và thông tin điều phối hàm.
- **Heap (Vùng nhớ động)**: Phân vùng bộ nhớ lớn hơn dùng cho việc cấp phát động trong quá trình chạy chương trình, lập trình viên cần chủ động cấp phát và giải phóng vùng nhớ này.
- **Buffer (Bộ đệm)**: Vùng bộ nhớ liên tiếp được dùng để lưu trữ dữ liệu tạm thời.
- **Bounds Checking (Kiểm tra biên)**: Cơ chế kiểm tra xem dữ liệu được ghi vào bộ nhớ có vượt quá kích thước giới hạn được cấp phát hay không.
- **Pointer (Con trỏ)**: Biến đặc biệt chứa địa chỉ ô nhớ của một biến hoặc đối tượng khác trong bộ nhớ.
- **Return Address (Địa chỉ trả về)**: Giá trị lưu trên stack giúp CPU biết cần thực hiện tiếp lệnh nào sau khi hàm hiện tại kết thúc.
- **Shellcode**: Một đoạn mã máy nhị phân nhỏ được kẻ tấn công chèn vào bộ nhớ nhằm chiếm quyền kiểm soát hệ thống (ví dụ: mở shell điều khiển).
- **Use-After-Free (UAF)**: Lỗi bảo mật xảy ra khi chương trình truy cập một con trỏ trỏ đến vùng nhớ đã bị giải phóng trước đó.
- **ASLR (Address Space Layout Randomization)**: Cơ chế an ninh của hệ điều hành giúp ngẫu nhiên hóa vị trí của các phân vùng bộ nhớ chính để ngăn kẻ tấn công đoán trước địa chỉ thực thi.
- **DEP/NX (Data Execution Prevention / No-Execute)**: Tính năng ngăn chặn việc thực thi mã lệnh trên các vùng nhớ chỉ dành cho việc chứa dữ liệu (như Stack hay Heap).
- **ROP (Return-Oriented Programming)**: Kỹ thuật tấn công nâng cao xâu chuỗi các đoạn mã máy ngắn có sẵn kết thúc bằng lệnh `ret` (gadget) để vượt qua bảo vệ DEP.

## 16. Bài liên quan và đọc thêm

- [Các bài học liên quan trong cùng thư mục](../)

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-120. https://cwe.mitre.org/data/definitions/120.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE-416. https://cwe.mitre.org/data/definitions/416.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** CWE-134. https://cwe.mitre.org/data/definitions/134.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S5]** CWE-190. https://cwe.mitre.org/data/definitions/190.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
