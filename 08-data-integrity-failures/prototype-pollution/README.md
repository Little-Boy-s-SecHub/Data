# Prototype Pollution

> **CWE**: CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes) | **Phân loại**: Data Integrity

## Kiến thức Nền tảng
Hãy tưởng tượng JavaScript là một xã hội phong kiến, nơi các đối tượng (objects) được sinh ra luôn kế thừa tài sản, danh hiệu hay thói quen từ tổ tiên của mình. Cơ chế này được gọi là **kế thừa nguyên mẫu (prototype inheritance)**. Mối liên kết gia phả này được kết nối bằng một sợi dây vô hình tên là `__proto__`, tạo nên một **chuỗi nguyên mẫu (prototype chain)**.

Khi bạn hỏi một đối tượng: "Bạn có kỹ năng X không?", trước tiên nó sẽ lục tìm trong ví của mình. Nếu không có, nó sẽ hỏi bố nó (thông qua `__proto__`), nếu bố nó cũng không có thì hỏi ông nội, cứ như thế tìm ngược lên cho đến khi gặp cụ tổ tối cao của mọi đối tượng trong JavaScript: **`Object.prototype`**. Nếu ngay cả cụ tổ cũng không có kỹ năng đó, đối tượng mới đành trả lời là không tìm thấy.

Vì `Object.prototype` là cụ tổ tối cao, nên bất cứ thứ gì cụ tổ sở hữu (như các hàm cơ bản `toString` hay `hasOwnProperty`), tất cả con cháu sinh ra đời sau đều mặc nhiên được thừa hưởng.

Tấn công Prototype Pollution khai thác sự thiếu sót trong việc kiểm tra các thuộc tính đặc biệt này (`__proto__`, `constructor`, `prototype`) khi ứng dụng thực hiện gộp đối tượng (merge) hoặc gán thuộc tính một cách đệ quy từ dữ liệu do người dùng kiểm soát. Khi kẻ tấn công chèn được thuộc tính độc hại vào `Object.prototype`, mọi đối tượng mới được tạo ra sau đó sẽ tự động kế thừa thuộc tính này, dẫn đến các lỗ hổng nghiêm trọng như vượt qua cơ chế phân quyền (bypass authorization) hoặc thực thi mã từ xa (RCE).

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

## Mô tả lỗ hổng
Lỗ hổng **Prototype Pollution (Ô nhiễm nguyên mẫu)** là một căn bệnh đặc hữu của thế giới JavaScript. Nó xảy ra khi ứng dụng cho phép người dùng tùy ý ghi đè các thuộc tính gia phả mà không có sự kiểm duyệt chặt chẽ. Kẻ tấn công chỉ cần lén gửi một yêu cầu chứa các từ khóa nhạy cảm như `__proto__` hay `constructor.prototype` để "bơm" thuộc tính độc hại vào cụ tổ `Object.prototype`.

Khi cụ tổ đã bị nhiễm độc, hành vi của toàn bộ hệ thống JavaScript sẽ bị xoay chuyển. Kẻ tấn công có thể lợi dụng điều này để:
- Vượt qua các chốt kiểm tra quyền hạn (ví dụ tự động gán vai trò quản trị viên cho mọi đối tượng người dùng).
- Chèn các đoạn mã script nguy hại để tấn công người dùng trực tiếp trên trình duyệt (Client-side XSS).
- Chiếm quyền điều khiển máy chủ và chạy các câu lệnh hệ thống từ xa (RCE) nếu ứng dụng chạy trên nền Node.js.

## Cơ chế tấn công
Lỗ hổng thường xuất hiện qua 3 biến thể chính:

### 1. Server-side Prototype Pollution dẫn đến RCE
Khi ứng dụng Node.js sử dụng các hàm như `child_process.fork()`, `child_process.spawn()`, hoặc `child_process.execSync()` mà không cấu hình đầy đủ các tham số (hoặc truyền đối tượng options rỗng), Node.js sẽ kiểm tra `Object.prototype` để lấy các cấu hình mặc định nếu chúng không được định nghĩa rõ ràng. Kẻ tấn công có thể lợi dụng điều này để làm ô nhiễm các thuộc tính cấu hình hệ thống:
- **`execArgv`**: Mảng các tham số truyền cho Node.js binary. Ô nhiễm thuộc tính này thành `["--eval", "payload"]` giúp thực thi mã trực tiếp khi Node.js tạo tiến trình con qua `fork()`.
- **`NODE_OPTIONS` (thông qua `env`)**: Nếu tiến trình con được sinh ra với một đối tượng `options.env` tùy chỉnh (ví dụ: `spawn('node', [], {env: {}})`), đối tượng này sẽ kế thừa thuộc tính từ `Object.prototype`. Nếu kẻ tấn công làm ô nhiễm `Object.prototype.NODE_OPTIONS = "--require=/tmp/payload.js"`, Node.js sẽ tải và thực thi mã độc tại thời điểm tiến trình con được khởi tạo.

### 2. Client-side Prototype Pollution dẫn đến XSS (XSS Chains via innerHTML)
Trên môi trường trình duyệt, nếu kẻ tấn công ô nhiễm được `Object.prototype`, họ có thể nhắm vào các đoạn mã JavaScript của ứng dụng (DOM Gadgets) mà thực hiện gán thuộc tính vào DOM mà không kiểm tra tính hợp lệ.
Ví dụ điển hình là các đoạn mã khởi tạo phần tử HTML bằng cách lấy giá trị cấu hình:
```javascript
let config = getConfiguration() || {};
let div = document.createElement("div");
div.innerHTML = config.html || "Default Content";
```
Nếu `config.html` không tồn tại, trình duyệt tìm kiếm trên chuỗi prototype. Nếu kẻ tấn công đã ô nhiễm `Object.prototype.html = "<img src=x onerror=alert(document.cookie)>"`, giá trị này sẽ được gán thẳng vào thuộc tính `innerHTML` và kích hoạt XSS.

### 3. Lỗi cụ thể trong các thư viện (Library-specific)
Nhiều phiên bản cũ của các thư viện tiện ích phổ biến như `lodash` (hàm `lodash.merge`, `lodash.defaultsDeep`) hoặc `jQuery` (hàm `jQuery.extend` thực hiện deep copy) gặp lỗi khi xử lý các khóa đệ quy.
- **`lodash.merge` (các phiên bản < 4.17.12)**: Cho phép kẻ tấn công truyền một đối tượng JSON chứa khóa `__proto__` để ghi đè thuộc tính toàn cục.
- **`jQuery.extend` (các phiên bản < 3.4.0)**: Khi thực hiện gộp sâu (deep copy) với tham số đầu tiên là `true`, hàm này không kiểm tra khóa `__proto__`, cho phép ghi đè các phương thức/thuộc tính trên `Object.prototype`.

## Biện pháp phòng thủ
- **Tóm tắt**: Ngăn chặn Prototype Pollution bằng cách đóng băng nguyên mẫu Object.prototype, sử dụng các object không có prototype, và cập nhật các thư viện an toàn.
- **Các bước chi tiết**:
  - **Đóng băng nguyên mẫu (Prototype Freezing)**: Gọi `Object.freeze(Object.prototype)` ở đầu ứng dụng để ngăn chặn mọi hành vi chỉnh sửa thuộc tính của đối tượng cơ sở.
  - **Sử dụng đối tượng không có Prototype**: Khởi tạo các đối tượng lưu trữ dữ liệu dạng key-value bằng `Object.create(null)` để loại bỏ hoàn toàn liên kết nguyên mẫu, ngăn ngừa các cơ chế tra cứu chuỗi prototype.
  - **Sử dụng thư viện an toàn & Cập nhật thường xuyên**: Sử dụng các phiên bản mới nhất của `lodash` (>= 4.17.12) và `jQuery` (>= 3.4.0) vốn đã được tích hợp cơ chế lọc các khóa nhạy cảm (`__proto__`, `constructor`, `prototype`).
  - **Lọc khóa dữ liệu đầu vào**: Khi tự xây dựng hàm merge hoặc parse JSON, luôn thực hiện kiểm tra và loại bỏ các khóa nhạy cảm trước khi gộp đối tượng.

## Code Example
### Vulnerable Code Example (Server-side RCE & Client XSS Gadget)
```javascript
const child_process = require('child_process');
const lodash = require('lodash'); // Vulnerable version, e.g., 4.17.11

// 1. Vulnerable Server-side Merge causing RCE
function handleUserPreferences(userJson) {
  let preferences = {};
  // Vulnerable merge operation using outdated lodash version
  lodash.merge(preferences, JSON.parse(userJson));
  
  // Later in the application, a child process is forked
  // If Object.prototype.execArgv was polluted, it will be executed here
  child_process.fork('./worker.js');
}

// 2. Vulnerable Client-side Gadget (Simulated)
function renderWidget(widgetConfigJson) {
  let config = {};
  // Vulnerable merge
  lodash.merge(config, JSON.parse(widgetConfigJson));
  
  const container = document.createElement('div');
  // Vulnerable DOM gadget: fallback to prototype property if 'html' is undefined
  const contentHtml = config.html || "<span>Default widget content</span>";
  container.innerHTML = contentHtml; // XSS trigger
}

// Example payloads:
// Server RCE: handleUserPreferences('{"__proto__": {"execArgv": ["--eval", "require(\'child_process\').execSync(\'id\')"]}}')
// Client XSS: renderWidget('{"__proto__": {"html": "<img src=x onerror=alert(1)>"}}')
```

### Secure Code Example
```javascript
const child_process = require('child_process');

// Prevent any changes to the global Object prototype at the entrypoint
Object.freeze(Object.prototype);

// Safe merge function with explicit key sanitization
function safeMerge(target, source) {
  for (let key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      // Reject dangerous keys to prevent prototype pollution
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        continue;
      }
      
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

// Safe usage of child process execution by freezing prototype and isolating env
function runSafeWorker() {
  const options = {
    // Explicitly define execArgv to override any potential polluted property
    execArgv: [],
    // Provide a fresh environment object or filter env properties
    env: Object.assign(Object.create(null), process.env) 
  };
  child_process.fork('./worker.js', [], options);
}

// Safe client-side rendering using sanitization and clean objects
function renderSafeWidget(widgetConfigJson) {
  // Use a clean map without prototype
  const config = Object.create(null);
  const parsed = JSON.parse(widgetConfigJson);
  
  // Sanitized merge
  safeMerge(config, parsed);
  
  const container = document.createElement('div');
  // Safe default lookup (doesn't inherit from Object.prototype)
  const contentHtml = config.html || "<span>Default widget content</span>";
  
  // In real applications, sanitization (e.g. DOMPurify) should be used before innerHTML
  container.textContent = contentHtml; // Safer alternative to innerHTML
}
```

## Xem thêm
- [Insecure Deserialization](../insecure-deserialization/) — Lỗ hổng giải tuần tự hóa không an toàn thường kết hợp với Prototype Pollution để khai thác các đối tượng trong môi trường runtime.

## Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/prototype-pollution
- OWASP: https://owasp.org/www-pdf-archive/OWASP_Top_10_2021_Draft_v1.1.pdf
- CWE: https://cwe.mitre.org/data/definitions/1321.html

## Giải thích thuật ngữ
- **Prototype Inheritance (Kế thừa nguyên mẫu)**: Cơ chế trong JavaScript cho phép các đối tượng kế thừa thuộc tính và phương thức từ một đối tượng nguyên mẫu khác để tái sử dụng mã nguồn.
- **Prototype Chain (Chuỗi nguyên mẫu)**: Chuỗi liên kết các đối tượng thông qua thuộc tính `__proto__` dùng để tra cứu thuộc tính từ cấp con lên cấp cha và các tổ tiên xa hơn.
- **`__proto__`**: Một thuộc tính đặc biệt trong JavaScript trỏ tới đối tượng nguyên mẫu (prototype) trực tiếp của đối tượng hiện tại.
- **`Object.prototype`**: Đối tượng cơ sở cao nhất, đóng vai trò là "cụ tổ" của hầu như toàn bộ đối tượng trong JavaScript.
- **Merge (Gộp đối tượng)**: Hành động kết hợp các thuộc tính từ nhiều đối tượng khác nhau thành một đối tượng duy nhất.
- **XSS (Cross-Site Scripting)**: Lỗ hổng chèn mã độc JavaScript vào trang web để thực thi trên trình duyệt của nạn nhân.
- **Client-side**: Phía máy khách, đề cập đến các hoạt động và mã nguồn chạy trực tiếp trên thiết bị (trình duyệt) của người dùng.
- **DOM (Document Object Model)**: Giao diện lập trình ứng dụng dạng cây dùng để biểu diễn và tương tác với các cấu trúc tài liệu HTML/XML của trang web.
- **DOM Gadget**: Đoạn mã JavaScript hợp lệ có sẵn trên trang web nhưng có thể bị lợi dụng để kích hoạt lỗ hổng bảo mật (như XSS) khi kết hợp với đầu vào bị kiểm soát.
- **Deep Copy (Sao chép sâu)**: Sao chép một đối tượng bằng cách tạo ra các bản sao vật lý mới cho cả các đối tượng con nằm sâu bên trong nó, thay vì chỉ sao chép tham chiếu.
