# Buffer Overflows

> **CWE**: CWE-120, CWE-476 | **Phân loại**: System / Binary

## Kiến thức Nền tảng
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

## Mô tả lỗ hổng
Lỗ hổng **Buffer Overflow (Tràn bộ đệm)** giống như việc cố gắng đổ một lít nước vào một chiếc ly chỉ chứa được 200ml. Nước sẽ tràn ra bàn, làm ướt sũng các tài liệu quan trọng xung quanh.

Trong thế giới phần mềm, khi ứng dụng ghi dữ liệu vượt giới hạn cho phép vào một bộ đệm có kích thước cố định mà không kiểm tra độ dài trước, dữ liệu dư thừa sẽ tràn ra và đè lên các vùng nhớ liền kề.
Lỗ hổng này cực kỳ nguy hiểm bởi vì:
- Nó có thể lập tức làm sập ứng dụng (Crash), gây gián đoạn dịch vụ.
- Nghiêm trọng hơn, kẻ tấn công có thể chèn vào một đoạn mã máy độc hại (shellcode), rồi ghi đè địa chỉ trả về của hàm để ép CPU thực thi đoạn mã độc đó, dẫn đến chiếm quyền điều khiển hoàn toàn hệ thống từ xa.

## Cơ chế tấn công
Tấn công tràn bộ đệm có nhiều biến thể tùy thuộc vào phân vùng bộ nhớ (Stack, Heap) và kiểu dữ liệu bị thao túng:

1. **Stack-based Buffer Overflow (Tràn bộ đệm trên Stack)**:
   Kẻ tấn công gửi đầu vào vượt quá kích thước bộ đệm trên Stack (ví dụ qua các hàm không an toàn như `gets()`, `strcpy()`). Dữ liệu thừa ghi đè lên địa chỉ trả về (Return Address) của stack frame hiện tại. Khi hàm thực hiện lệnh `ret` (return), CPU sẽ nhảy tới địa chỉ bị ghi đè này (có thể là địa chỉ chứa shellcode trên stack được đệm bởi NOP sled hoặc địa chỉ của một hàm hệ thống).

2. **Heap Overflow (Tràn bộ đệm trên Heap & UAF)**:
   - **Heap Overflow**: Kẻ tấn công ghi ghi dữ liệu vượt quá kích thước vùng nhớ được cấp phát động (heap chunk) thông qua các hàm như `malloc()`. Dữ liệu tràn ra sẽ ghi đè lên cấu trúc siêu dữ liệu (metadata) của các chunk liền kề, chẳng hạn như kích thước hoặc con trỏ của chunk tiếp theo. Khi chương trình thực hiện giải phóng (`free()`) hoặc cấp phát lại (`malloc()`), cơ chế quản lý heap của hệ thống (ví dụ: `dlmalloc` hay `ptmalloc`) sẽ xử lý các con trỏ bị giả mạo này, dẫn đến ghi đè bộ nhớ tùy ý (arbitrary write) hoặc lỗi UAF.
   - **Use-After-Free (UAF)**: Xảy ra khi một con trỏ vẫn được sử dụng sau khi vùng nhớ mà nó trỏ tới đã bị giải phóng (`free()`). Nếu kẻ tấn công có thể chèn một đối tượng mới có cấu trúc tương tự (nhưng chứa dữ liệu hoặc con trỏ hàm do kẻ tấn công kiểm soát) vào đúng vị trí vùng nhớ vừa được giải phóng đó, khi chương trình gọi lại con trỏ cũ, luồng thực thi sẽ bị chuyển hướng.

3. **Format String Vulnerability (%x leak, %n arbitrary write)**:
   Xảy ra khi dữ liệu người dùng nhập được truyền trực tiếp làm chuỗi định dạng (format string) trong các hàm thuộc họ `printf(user_input)` thay vì `printf("%s", user_input)`.
   - **%x / %p (Leak stack)**: Kẻ tấn công gửi chuỗi chứa nhiều ký tự `%x` hoặc `%p` để đọc dữ liệu trên stack. Kỹ thuật này giúp rò rỉ các giá trị nhạy cảm như Canary, địa chỉ trả về để tính toán địa chỉ gốc của thư viện (bypass ASLR).
   - **%n (Arbitrary write)**: Ký tự đặc biệt `%n` ghi số lượng byte đã được in trước đó vào địa chỉ được trỏ bởi đối số tương ứng trên stack. Bằng cách điều khiển cấu trúc stack và số lượng ký tự in ra, kẻ tấn công có thể ghi đè một giá trị tùy ý vào một địa chỉ bộ nhớ bất kỳ (ví dụ: ghi đè địa chỉ trả về hoặc Global Offset Table - GOT).

4. **Integer Overflow (Signed/Unsigned Wraparound)**:
   Xảy ra khi một phép toán số học vượt quá giới hạn lưu trữ tối đa hoặc tối thiểu của kiểu dữ liệu số nguyên.
   - **Unsigned Overflow**: Phép cộng vượt ngưỡng sẽ quay vòng về `0` (wraparound).
   - **Signed Overflow**: Phép cộng vượt ngưỡng có thể làm thay đổi bit dấu, chuyển số dương thành số âm.
   Kẻ tấn công lợi dụng việc tràn số nguyên để vượt qua cơ chế kiểm tra độ dài đầu vào. Ví dụ, biểu thức kiểm tra kích thước bộ đệm `length + 1` có thể bị tràn và quay về `0` nếu `length` bằng giá trị tối đa (ví dụ: `65535` đối với `unsigned short`). Khi đó, chương trình cấp phát bộ đệm kích thước `0` byte nhưng sau đó sao chép một lượng dữ liệu khổng lồ vào, dẫn đến tràn bộ đệm heap hoặc stack.

5. **ROP Chains Overview (Gadgets & DEP Bypass)**:
   Khi hệ điều hành kích hoạt cơ chế phòng thủ **DEP/NX** (Data Execution Prevention / No-Execute), ngăn xếp và bộ nhớ heap không được phép thực thi lệnh, kẻ tấn công không thể chạy trực tiếp shellcode được chèn vào. Để bypass DEP, kẻ tấn công sử dụng kỹ thuật **Return-Oriented Programming (ROP)**.
   - **ROP Gadgets**: Kẻ tấn công tìm các đoạn lệnh máy ngắn kết thúc bằng lệnh `ret` trong mã nguồn của chương trình hoặc các thư viện dùng chung (như libc) gọi là các "gadget".
   - **ROP Chain**: Bằng cách xếp chồng liên tục các địa chỉ của các gadget này lên ngăn xếp (stack), luồng thực thi của chương trình sẽ thực hiện tuần tự từng gadget một. Chuỗi ROP (ROP chain) này có thể thiết lập các thanh ghi chứa tham số và gọi các hàm hệ thống có sẵn (như `mprotect()` để chuyển vùng nhớ sang chế độ thực thi, hoặc gọi trực tiếp `execve("/bin/sh")`) nhằm chiếm quyền điều khiển.

## Biện pháp phòng thủ
- **Tóm tắt**: Ngăn chặn tràn bộ đệm bằng cách sử dụng các hàm thao tác bộ nhớ an toàn, thực thi kiểm tra biên và kích hoạt các cơ chế phòng thủ ở cấp độ hệ điều hành và thời gian biên dịch.
- **Các bước chi tiết**:
  - Sử dụng các giải pháp thay thế kiểm tra biên an toàn (như fgets hoặc snprintf) thay vì các hàm chuỗi C không an toàn như gets hoặc scanf.
  - Thực thi các xác thực độ dài đầu vào nghiêm ngặt để ngăn chặn đầu vào vượt quá dung lượng bộ đệm đích.
  - Biên dịch ứng dụng với các bộ bảo vệ ngăn xếp/canary (stack protectors/canaries) và các cảnh báo trong thời gian biên dịch (ví dụ: -fstack-protector).
  - Triển khai các biện pháp bảo vệ ở cấp độ hệ điều hành như Ngẫu nhiên hóa sơ đồ bố trí không gian địa chỉ (ASLR) và Ngăn chặn thực thi dữ liệu (DEP/NX).

## Code Example
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

### 4. Heap Overflow & Use-After-Free (UAF)
```c
// === VULNERABLE: Use-After-Free with dangling pointer ===
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    void (*callback)(const char *);
    char name[24];
} UserSession;

void vuln_uaf_flow() {
    UserSession *session = (UserSession *)malloc(sizeof(UserSession));
    session->callback = printf;
    strcpy(session->name, "GuestUser");

    // Freeing the memory block but keeping the pointer (dangling pointer)
    free(session);

    // Attacker requests allocation of the same size to hijack the memory block
    char *attacker_payload = (char *)malloc(sizeof(UserSession));
    // Overwrite the first 8 bytes (which corresponds to the callback function pointer)
    strcpy(attacker_payload, "\xde\xad\xbe\xef"); 

    // Dangerous: calls the function pointer from the freed/re-allocated struct
    session->callback(session->name);
}

// === SECURE: Erasing references post-deallocation ===
#include <stdio.h>
#include <stdlib.h>

void secure_uaf_flow() {
    UserSession *session = (UserSession *)malloc(sizeof(UserSession));
    if (session == NULL) return;
    session->callback = printf;
    
    // Safe: free memory and immediately nullify the dangling pointer
    free(session);
    session = NULL;
}
```

### 5. Return-Oriented Programming (ROP) Concept
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

## Xem thêm
- [Các bài học liên quan trong cùng thư mục](../)

## Nguồn tham khảo
- **Nguồn tham khảo**: CWE-120 (Buffer Copy without Checking Size of Input), CWE-476 (NULL Pointer Dereference)

## Giải thích thuật ngữ
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
