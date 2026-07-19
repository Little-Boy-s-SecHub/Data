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
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Buffer Overflows by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploitable.
- Conduct controlled testing in a local lab and distinguish between expected results and false positives.
- Choose root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow in Buffer Overflows scenarios and how to apply input handling across trust boundaries.  
- Differentiate between authentication, authorization, and validation.  
- Be able to read code/configuration in the language or framework appearing in the example.  
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine computer memory like a series of consecutive storage drawers. When running a program, the computer divides these drawers into two different management areas:
- **Stack**: Like a narrow vertical box where you pile documents on top of each other. The document placed last will be taken out first (LIFO). It stores temporary variables and especially a note called the "Return Address." When a function finishes running, the program reads this note to know what task to resume outside. This memory area is extremely fast but very small.
- **Heap**: Like a large flexible warehouse where the programmer has to actively rent space (using functions like malloc/free) and release it when done. This warehouse is much more spacious but retrieving items is a bit slower.

In low-level programming languages like C/C++, buffer allocation (**Buffer Allocation**) is simply arranging a series of adjacent storage cells. The frightening thing is, these languages do not have anyone guarding to check whether the data you put in exceeds the size of the storage cell (lack of bounds checking).

If you use a pointer – like a pen that writes addresses – to write data longer than the size of the allocated slot, the pen will not automatically stop at the boundary line. It will continue writing into adjacent slots, overwriting and destroying all the system’s old data. On the Stack, this overwriting can hit the 'return address' note (EIP/RIP) directly. When the function ends, CPU reads this forged address and jumps straight to the attacker’s malicious code (shellcode) instead of returning to do the usual work.

### Illustration of normal operation (Normal Operation)```c
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

## 4. Description and Root Cause

A **Buffer Overflow** vulnerability is like trying to pour a liter of water into a glass that can only hold 200ml. The water will spill onto the table, soaking the important documents around it.

In the software world, when an application writes data that exceeds the allowed limit into a fixed-size buffer without checking the length beforehand, the excess data will overflow and overwrite adjacent memory areas.  
This vulnerability is extremely dangerous because:  
- It can immediately crash the application, causing service interruptions.  
- More seriously, an attacker can insert a piece of malicious machine code (shellcode), then overwrite the function's return address to force CPU to execute that malicious code, leading to full remote control of the system.

> **Reference:** the technical claims in the lesson are marked with a source; when applying in practice, cross-check with the version/framework being used: [S1], [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** integrity of memory, control flow, and data adjacent to the toy process buffer.  
- **Trust boundary:** bytes from `argv`/stdin are copied or measured for length before writing into a fixed-size C buffer.  
- **Actor:** local user in the container, only providing input to the binary fixture; no network listener or shellcode callback.  
- **Necessary conditions:** the write lacks length checking or has integer truncation/overflow; input actually reaches the sink; the crash is only evidence of a memory error, not proof of control-flow compromise.  
- **Environmental conditions:** Ubuntu 22.04 x86-64, GCC 11.4 and glibc 2.35; AddressSanitizer build used to confirm out-of-bounds.

ASLR, NX, stack canary and PIE affect exploitability but do not fix out-of-bounds write; the flags of each build must be specified when interpreting the results. [S1]

## 6. Attack Mechanism

When the number of copied bytes is larger than the destination area, the write operation may touch the adjacent memory region; the observable result may be an ASan report, a crash, or a change in the nearby marker. Use-after-free, format string, and integer overflow are other root causes, only include them in the conclusion when the corresponding trace proves them. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** compile together with the source using GCC 11.4 with `-g -fsanitize=address -fno-omit-frame-pointer`; record separate build flags for the vulnerable version and the safe version.
2. **Input:** use the string ASCII with a maximum length of 256 bytes; baseline smaller than buffer size.
3. **Operation:** try sequentially sizes `N-1`, `N`, `N+1` and a limited cyclic string; save stderr/ASan trace and exit code.
4. **Expected result:** the vulnerable version produces ASan out-of-bounds at `N+1`; the safe version rejects overly long input, always null-terminates, and does not alter adjacent markers.
5. **Cleanup:** delete binary, core dump, and disposable container after saving test results.
6. **Safety limits:** no shellcode, do not disable host protections, do not open a listener; all processes have timeout, CPU and memory cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

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
Buffer overflow attacks have many variations depending on the memory region (Stack, Heap) and the type of data being manipulated:

1. **Stack-based Buffer Overflow**:
   An attacker sends input that exceeds the size of the buffer on the stack (for example, through unsafe functions like `gets()`, `strcpy()`). The excess data overwrites the return address of the current stack frame. When the function executes the instruction `ret` (return), CPU will jump to this overwritten address (which could be an address containing shellcode on the stack padded by an NOP sled or the address of a system function).

2. **Heap Buffer Overflow**:  
   An attacker writes data exceeding the size of the dynamically allocated memory. The data can corrupt adjacent objects or metadata; the specific impact depends on the allocator, layout, and hardening of the fixture version. **Use-After-Free** is a separate weakness (CWE-416), not a variant of buffer overflow. [S3]

3. **Related but Different Weakness: Format String (CWE-134)** [S4]:
   Occurs when user input data is directly passed as a format string in functions belonging to the `printf(user_input)` family instead of `printf("%s", user_input)`.
   - **%x / %p (Leak stack)**: The attacker sends a string containing many `%x` or `%p` characters to read data on the stack. This technique helps leak sensitive values such as Canary, return address to calculate the base address of the library (bypass ASLR).
   - **%n (Arbitrary write)**: The special character `%n` writes the number of bytes that have been printed so far to the address pointed to by the corresponding argument on the stack. By controlling the stack structure and the number of printed characters, the attacker can overwrite an arbitrary value to any memory address (e.g., overwrite the return address or the Global Offset Table - GOT).

4. **Related but different type of weakness: Integer Overflow (CWE-190)** [S5]:
   Occurs when an arithmetic operation exceeds the maximum or minimum storage limit of an integer data type.
   - **Unsigned overflow in C** has modulo $2^N$ semantics for an N-bit type.
   - **Signed overflow in C** is undefined behavior; it should not be assumed that the value always wraps around to a negative number.
   Attackers exploit integer overflow to bypass input length checks. For example, a buffer size checking expression `length + 1` can overflow and wrap to `0` if `length` equals the maximum value (e.g., `65535` for `unsigned short`). In this case, the program allocates a buffer of `0` bytes but then copies a huge amount of data into it, leading to a heap or stack buffer overflow.

5. **Exploitation technique, not the root cause: ROP (Gadgets & DEP bypass)**:
   When the operating system activates the defense mechanism **DEP/NX** (Data Execution Prevention / No-Execute), the stack and heap memory are not allowed to execute instructions, the attacker cannot directly run injected shellcode. To bypass DEP, the attacker uses the technique **Return-Oriented Programming (ROP)**.
   - **ROP Gadgets**: The attacker finds short machine code sequences ending with the `ret` instruction in the program's source code or shared libraries (such as libc), called “gadgets”.
   - **ROP Chain**: By continuously stacking the addresses of these gadgets on the stack, the program’s execution flow will sequentially execute each gadget. This ROP (ROP chain) can set registers containing parameters and call existing system functions (such as `mprotect()` to make a memory region executable, or directly call `execve("/bin/sh")`) to gain control.

## 9. Vulnerable Code and Secure Code

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

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Buffer Overflows, policy results and correlation ID; do not log secrets or the entire token. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior sequences, not just a single payload chain. 
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether there was any impact. 
- Scanner or WAF alerts are only investigative signals; they are not the sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Limit resources, fail safely, and handle all possible exceptional states.  
- Check sizes before every copy operation, use checked arithmetic/API with length or memory-safe language; compiler hardening is just defense-in-depth.  
- Use the same policy for all equivalent routes/operations; do not only fix the endpoint that appears in the PoC.

### Defense-in-depth

With Buffer Overflows, the following measures help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used as a replacement for original controls.

- **Summary**: Prevent buffer overflows by using safe memory manipulation functions, performing boundary checks, and enabling defense mechanisms at the operating system and compile-time levels.
- **Detailed steps**:
  - Use API with clear limits (such as `fgets` or `snprintf`) instead of `gets`, `strcpy`, or `scanf` which do not declare proper field width.
  - Perform strict input length validation to prevent input from exceeding the capacity of the target buffer.
  - Compile the application with stack/canary protectors and compile-time warnings (e.g., -fstack-protector).
  - Deploy operating system-level protections such as Address Space Layout Randomization (ASLR) and Data Execution Prevention (DEP/NX).

## 12. Retest

- **Positive case:** with Buffer Overflows, the valid flow still works correctly for allowed actors and data. 
- **Negative case:** with the same input/resources but disallowed actor or context, it should be rejected without leaking sensitive details. 
- **Boundary case:** check empty values, edge limits, different encodings, repeated requests, expired session states, and equivalent paths/operations. 
- **Telemetry:** confirm policy decisions, application logs, proxy logs, and datastore side effects match correlation ID. 
- **Re-test:** keep a minimal scenario that reproduces the old error and proves the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Buffer Overflows without verifying side effects and logs.  
- Use a payload with correct syntax but wrong DBMS, browser, framework, protocol, or injection context.  
- Consider UUID, rate limit, WAF, CSP, or general input validation as fixes for another original control.  
- Only fix one route while the same sink/policy is used on another route.  
- Conclude that a vulnerability exists without saving the source, fixture version, and observable proof.

## 14. Summary and Checklist

- [ ] Root cause, consequences, and exploitation techniques have been separated.  
- [ ] Actor, role/authentication, trust boundary, technology, and version are clear.  
- [ ] Payload has a unique ID, context, encoding, conditions, expected result, risk, validation, and source.  
- [ ] Code prone to errors/unsafe uses the same framework, version, and use case.  
- [ ] Mandatory controls cannot be replaced with defense-in-depth.  
- [ ] Positive, negative, boundary cases, and telemetry have been retested.  
- [ ] Sensitive technical claims have references in section 17, and all links are only in sections 16–17.  
- [ ] Cleanup is complete; no secrets, real targets, Internet callbacks, or customer data remain.

## 15. Glossary

- **Stack**: A memory section automatically managed according to the "last in, first out" mechanism, mainly used to store local variables and function control information.
- **Heap**: A larger memory section used for dynamic allocation during program execution, where programmers need to actively allocate and free this memory.
- **Buffer**: A contiguous memory area used to temporarily store data.
- **Bounds Checking**: A mechanism to check whether data written into memory exceeds the allocated size limit.
- **Pointer**: A special variable that contains the memory address of another variable or object in memory.
- **Return Address**: A value stored on the stack that helps know which instruction to execute next after the current function ends.
- **Shellcode**: A small binary code segment that attackers insert into memory to take control of the system (e.g., open a command shell).
- **Use-After-Free**: A security vulnerability that occurs when a program accesses a pointer that points to memory that has already been freed.
- **Address Space Layout Randomization (ASLR)**: An operating system security mechanism that randomizes the location of major memory sections to prevent attackers from predicting execution addresses.
- **Data Execution Prevention (DEP) / No-Execute (NX)**: A feature that prevents executing code in memory regions meant only for data (such as Stack or Heap).
- **Return-Oriented Programming (ROP)**: An advanced attack technique that chains together short existing machine code snippets ending with a gadget instruction to bypass security protections.

## 16. Related Lessons and Further Reading

- [Related lessons in the same folder ](../)

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.
- **[S2]** CWE-120. https://cwe.mitre.org/data/definitions/120.html — version/status: current version; accessed: 2026-07-18.
- **[S3]** CWE-416. https://cwe.mitre.org/data/definitions/416.html — version/status: current version; accessed: 2026-07-18.
- **[S4]** CWE-134. https://cwe.mitre.org/data/definitions/134.html — version/status: current version; accessed: 2026-07-18.
- **[S5]** CWE-190. https://cwe.mitre.org/data/definitions/190.html — version/status: current version; accessed: 2026-07-18.