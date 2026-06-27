# Prototype Pollution

> **OWASP Top 10:2025**: A08:2025 – Software/Data Integrity Failures | **CWE**: CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes) | **Phân loại**: Software and Data Integrity Failures

## 🧱 Kiến thức Nền tảng
Trong JavaScript, cơ chế kế thừa nguyên mẫu (prototype inheritance) cho phép các đối tượng kế thừa thuộc tính và phương thức từ một đối tượng khác, gọi là prototype của chúng. Chuỗi nguyên mẫu (prototype chain) là một danh sách liên kết các đối tượng, được liên kết thông qua thuộc tính `__proto__`. Khi truy cập một thuộc tính của đối tượng, JavaScript sẽ tìm kiếm trên chính đối tượng đó trước. Nếu không tìm thấy, nó sẽ duyệt ngược lên chuỗi prototype thông qua thuộc tính `__proto__` cho đến khi tìm thấy hoặc đạt tới đỉnh của chuỗi là `Object.prototype`.

`Object.prototype` là đối tượng cơ sở tối cao mà hầu hết các đối tượng JavaScript đều kế thừa trực tiếp hoặc gián tiếp. Nó chứa các phương thức dùng chung như `hasOwnProperty` hay `toString`.

Thuộc tính `__proto__` là một accessor property (gồm getter và setter) dùng để truy cập prototype của đối tượng. Thuộc tính `constructor` trỏ về hàm khởi tạo đã tạo ra đối tượng đó. Thông qua `obj.constructor.prototype`, ta cũng có thể truy cập prototype của hàm khởi tạo.

Tấn công Prototype Pollution khai thác sự thiếu sót trong việc kiểm tra các thuộc tính đặc biệt này (`__proto__`, `constructor`, `prototype`) khi ứng dụng thực hiện gộp đối tượng (merge) hoặc gán thuộc tính một cách đệ quy từ dữ liệu do người dùng kiểm soát. Khi kẻ tấn công chèn được thuộc tính độc hại vào `Object.prototype`, mọi đối tượng mới được tạo ra sau đó sẽ tự động kế thừa thuộc tính này, dẫn đến các lỗ hổng nghiêm trọng như vượt qua cơ chế phân quyền (bypass authorization) hoặc thực thi mã từ xa (RCE).

## 💻 Code Example: Normal Prototype Inheritance & Chain Lookup
```javascript
// Define a constructor function for a generic User
function User(name) {
  this.name = name;
}

// Add a method to the User prototype
User.prototype.sayHello = function() {
  return "Hello, my name is " + this.name;
};

// Create a new User instance
const alice = new User("Alice");

// Normal property lookup: 'name' is found directly on the 'alice' object
console.log(alice.name); // Output: "Alice"

// Prototype chain lookup: 'sayHello' is not defined on 'alice' itself,
// so JavaScript traverses the prototype chain (__proto__) to find it on User.prototype
console.log(alice.sayHello()); // Output: "Hello, my name is Alice"

// Accessing Object.prototype methods inherited by default on all objects
console.log(alice.hasOwnProperty("name")); // Output: true
```

## 🔍 Mô tả lỗ hổng
Ô nhiễm Prototype (Prototype Pollution) là một lỗ hổng đặc thù trong JavaScript, xảy ra khi kẻ tấn công có thể sửa đổi thuộc tính của đối tượng prototype chung (Object.prototype). Bằng cách tiêm các thuộc tính độc hại thông qua các tham số đầu vào (như __proto__), kẻ tấn công làm thay đổi hành vi của toàn bộ các đối tượng JavaScript được khởi tạo sau đó. Lỗ hổng này có thể dẫn tới bypass xác thực, rò rỉ dữ liệu hoặc thậm chí là thực thi mã từ xa (RCE) trên máy chủ Node.js.

## ⚔️ Cơ chế tấn công
Bước 1: Ứng dụng Node.js sử dụng một hàm gộp đối tượng đệ quy (merge) không an toàn để kết hợp dữ liệu JSON từ người dùng gửi lên.
Bước 2: Kẻ tấn công gửi một payload JSON có chứa thuộc tính đặc biệt ví dụ: `{"__proto__": {"isAdmin": true}}`.
Bước 3: Khi hàm merge xử lý đệ quy, nó truy cập thuộc tính `__proto__` của đối tượng mục tiêu (chính là nguyên mẫu `Object.prototype`) và gán giá trị `isAdmin = true` lên đó.
Bước 4: Từ thời điểm này, tất cả các đối tượng JavaScript mới được tạo ra trong ứng dụng đều kế thừa thuộc tính `isAdmin` với giá trị `true`, giúp kẻ tấn công bypass các kiểm tra phân quyền.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Prototype pollution occurs in JavaScript when user input is merged into an object without checking the keys, allowing modification of the global Object prototype (__proto__, constructor.prototype). Mitigation involves freezing prototypes, using Object.create(null) for map-like structures, validating schema inputs, or sanitizing keys.
- **Các bước chi tiết**:
  - Use safe object-merging libraries that explicitly filter out property names like '__proto__' and 'constructor'.
  - Create dictionaries and maps without prototype links using Object.create(null).
  - Freeze the prototype of standard objects using Object.freeze(Object.prototype) to prevent modifications.
  - Validate incoming JSON payloads against strict schemas (e.g., with AJV) to reject unexpected/reserved object keys.

## 💻 Code Example
```javascript
// Safe deep merge function that filters out prototype modification keys
function safeMerge(target, source) {
  for (let key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      // Prevent prototype pollution by checking __proto__, constructor, and prototype
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        continue;
      }
      // Fix: Ensure neither target[key] nor source[key] is null before checking typeof 'object'
      if (target[key] !== null && typeof target[key] === 'object' && 
          source[key] !== null && typeof source[key] === 'object') {
        safeMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  return target;
}

// Creating safe map objects without prototype inheritance
const safeMap = Object.create(null);
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Trong Milestone 2, bài học này đã được chỉnh sửa (FIXED). Sửa đổi phân loại từ 'File & Data' thành 'Software and Data Integrity Failures' cho chính xác. Hàm safeMerge đệ quy ban đầu bị crash nếu đầu vào null và không lọc các khóa nhạy cảm. Mã nguồn sau khi sửa đổi loại bỏ triệt để các thuộc tính nguy hại (__proto__, constructor, prototype) để ngăn chặn ô nhiễm prototype trong Node.js.
- **Nguồn tham khảo**: OWASP A08:2021, CWE-1321
