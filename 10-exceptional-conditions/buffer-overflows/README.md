# Buffer Overflows

> **OWASP Top 10:2025**: A10:2025 – Mishandling of Exceptional Conditions | **CWE**: CWE-120, CWE-476 | **Phân loại**: System

## 🧱 Kiến thức Nền tảng
Lỗ hổng Tràn bộ đệm (Buffer Overflow) xảy ra khi chương trình ghi dữ liệu vượt quá dung lượng cấp phát của bộ đệm, làm ghi đè lên các vùng nhớ liền kề. Để hiểu cơ chế của lỗ hổng này, chúng ta cần nắm vững ba khái niệm quản lý bộ nhớ ở cấp độ hệ thống:

1. **Memory stack vs heap (Bộ nhớ Stack so với Heap)**: Stack là vùng nhớ được quản lý tự động bởi CPU theo cơ chế LIFO (Vào sau Ra trước). Nó lưu trữ các biến cục bộ, tham số hàm và đặc biệt là địa chỉ trả về (return address) để luồng thực thi quay lại sau khi hàm kết thúc. Heap là vùng nhớ cấp phát động có kích thước lớn hơn nhiều, được quản lý thủ công bởi lập trình viên thông qua các hàm như `malloc`/`free` (C) hoặc `new`/`delete` (C++). Stack truy cập rất nhanh nhưng dung lượng nhỏ, trong khi Heap chậm hơn nhưng linh hoạt.
2. **Buffer allocation in C/C++ (Cấp phát bộ đệm)**: Trong C/C++, bộ đệm (buffer) chỉ là một dãy các ô nhớ liên tiếp. Bộ đệm trên stack được xác định kích thước cố định khi biên dịch (ví dụ: `char buf[16]`), còn bộ đệm trên heap được cấp phát động lúc chạy. C/C++ không có cơ chế tự động kiểm tra biên bộ nhớ (bounds checking), cho phép chương trình ghi dữ liệu tùy ý nếu lập trình viên không chủ động giới hạn.
3. **Pointer logic (Logic con trỏ)**: Con trỏ lưu trữ địa chỉ bộ nhớ và cho phép truy cập, ghi dữ liệu thông qua các phép toán số học con trỏ. Khi ghi vượt biên, con trỏ tiếp tục dịch chuyển và ghi đè dữ liệu lên các ô nhớ tiếp theo. Trên stack, việc tràn bộ đệm có thể ghi đè lên EIP/RIP (con trỏ địa chỉ trả về của hàm). Khi hàm thực hiện lệnh return, CPU sẽ nhảy đến địa chỉ bị ghi đè đó, cho phép kẻ tấn công chuyển hướng luồng thực thi sang shellcode hoặc gây crash chương trình.

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

## 🔍 Mô tả lỗ hổng
Tràn bộ đệm (buffer overflow) xảy ra khi một chương trình ghi nhiều dữ liệu vào một khối bộ nhớ có kích thước cố định hơn dung lượng được phân bổ của nó, ghi đè lên bộ nhớ liền kề. Các ngôn ngữ lập trình cấp thấp như C/C++ yêu cầu phải xác thực kích thước thủ công. Khi quyền kiểm soát thực thi bị ghi đè, kẻ tấn công có thể làm sập ứng dụng hoặc chạy các payload nhị phân tùy ý (shellcode).

## ⚔️ Cơ chế tấn công
Kẻ tấn công gửi đầu vào (chẳng hạn như một tên người dùng dài) vượt quá kích thước bộ đệm. Trong mã nguồn C sử dụng các hàm không an toàn như gets() hoặc scanf("%s"), các ký tự thừa sẽ làm tràn bộ đệm, làm hỏng địa chỉ trả về của stack frame, và chuyển hướng thực thi đến một dải NOP (NOP sled) dẫn đến shellcode được chèn của kẻ tấn công.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Ngăn chặn tràn bộ đệm bằng cách sử dụng các hàm thao tác bộ nhớ an toàn, thực thi kiểm tra biên và kích hoạt các cơ chế phòng thủ ở cấp độ hệ điều hành và thời gian biên dịch.
- **Các bước chi tiết**:
  - Sử dụng các giải pháp thay thế kiểm tra biên an toàn (như fgets hoặc snprintf) thay vì các hàm chuỗi C không an toàn như gets hoặc scanf.
  - Thực thi các xác thực độ dài đầu vào nghiêm ngặt để ngăn chặn đầu vào vượt quá dung lượng bộ đệm đích.
  - Biên dịch ứng dụng với các bộ bảo vệ ngăn xếp/canary (stack protectors/canaries) và các cảnh báo trong thời gian biên dịch (ví dụ: -fstack-protector).
  - Triển khai các biện pháp bảo vệ ở cấp độ hệ điều hành như Ngẫu nhiên hóa sơ đồ bố trí không gian địa chỉ (ASLR) và Ngăn chặn thực thi dữ liệu (DEP/NX).

## 💻 Code Example
```c
// Safe C code replacing unsafe strcpy with snprintf and size limits
#include <stdio.h>
#include <string.h>

void process_input(const char *user_input) {
    if (user_input == NULL) {
        return;
    }
    char buffer[32];
    
    // Safe: snprintf limits writing to the buffer size and ensures null-termination
    snprintf(buffer, sizeof(buffer), "%s", user_input);
    printf("Processed buffer: %s\n", buffer);
}
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã sửa tệp oops.c trong Slide 3, vốn chứa mã tự do ở phạm vi tệp và thiếu khai báo hàm askForUsername. Giải quyết một lỗi dereference con trỏ NULL tiềm ẩn trong hàm phòng thủ process_input.
- **Nguồn tham khảo**: CWE-120 (Buffer Copy without Checking Size of Input), CWE-476 (NULL Pointer Dereference)
