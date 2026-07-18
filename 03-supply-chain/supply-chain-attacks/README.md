---
schema_version: 1
id: WEB-A03-SUPPLY-CHAIN-ATTACKS
title: "Supply Chain Attacks (CI/CD Pipeline)"
slug: supply-chain-attacks
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A08:2025
cwe:
  - CWE-829
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Supply Chain Attacks (CI/CD Pipeline)

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Supply Chain Attacks (CI/CD Pipeline) bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Dependency graph, build pipeline và artifact provenance.

- Registry resolution, lockfile và lifecycle script.

- Trust boundary giữa source, CI runner, registry và deployment.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn đang xây dựng một ngôi nhà. Thay vì tự mình đúc từng viên gạch, rèn từng chiếc đinh hay chế tạo xi măng từ đầu, bạn sẽ ra cửa hàng vật liệu xây dựng để mua các sản phẩm làm sẵn về lắp ghép. Ngôi nhà của bạn sẽ được hoàn thành rất nhanh chóng. Thế nhưng, nếu một kẻ xấu lẻn vào nhà máy sản xuất gạch và trộn thuốc nổ vào đất sét, hoặc đánh tráo những chiếc đinh thép thành đinh sắt rỗng, ngôi nhà của bạn dù được xây dựng đúng kỹ thuật đến đâu cũng sẽ đứng trước nguy cơ đổ sập. [S8]

Chuỗi cung ứng phần mềm gồm source, dependency, công cụ build, pipeline, artifact và các dịch vụ tham gia đưa phần mềm tới môi trường chạy. Tỷ lệ mã bên thứ ba thay đổi mạnh theo sản phẩm nên bài không dùng một con số phần trăm chung. Root cause cần chỉ rõ trust boundary nào chấp nhận source/artifact không được phê duyệt, không được khóa hoặc thiếu provenance/integrity phù hợp. [S2], [S8]

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
      - run: npm install                  # May update the lockfile/dependency tree
      - run: npm run build                # Build application
      - run: npm test                     # Run tests
      - run: docker build -t myapp .      # Create container image
      - run: docker push registry/myapp   # Push to artifact registry
```

Mỗi bước trên đều là một điểm mà attacker có thể can thiệp: từ việc chèn mã độc vào dependency, đến việc compromise GitHub Action, hay thay đổi base Docker image. [S8]

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Tấn công chuỗi cung ứng** (Supply Chain Attack) xảy ra khi kẻ tấn công không tìm cách hack trực tiếp vào hệ thống phòng thủ của bạn, mà đi đường vòng bằng cách **tấn công vào các thành phần bên ngoài** mà bạn hoàn toàn tin tưởng và sử dụng hàng ngày. [S8]

Đây là một trong những mối đe dọa nguy hiểm nhất hiện nay vì các nhà phát triển thường có tâm lý tin tưởng mù quáng vào các gói thư viện phổ biến hoặc các công cụ tự động. Kẻ tấn công có thể sử dụng nhiều chiêu trò tinh vi:
- **Dependency Confusion (Nhầm lẫn thư viện)**: Lợi dụng sơ hở trong cấu hình để lừa máy chủ tải một thư viện độc hại có trùng tên với thư viện nội bộ của công ty nhưng được đẩy phiên bản (version) lên mức siêu cao trên các kho lưu trữ công cộng.
- **Typosquatting (Đặt tên gần giống)**: Đăng ký các gói thư viện có tên viết sai chính tả gần giống các thư viện nổi tiếng (như `lodahs` thay vì `lodash`) để chờ đợi các lập trình viên gõ nhầm và tải về.
- **Compromised Maintainer (Chiếm đoạt tài khoản nhà phát triển)**: Hack tài khoản của người quản trị một thư viện phổ biến để âm thầm cài cắm mã độc vào bản cập nhật tiếp theo.
- **CI/CD Poisoning (Đầu độc hệ thống tự động)**: Chèn các đoạn script độc hại vào các cấu hình tự động xây dựng để đánh cắp các mật khẩu và khóa bảo mật (secrets) của doanh nghiệp. [S8]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** source, dependency graph, build artifact và CI secret synthetic.

- **Actor:** maintainer/dependency/CI action không tin cậy trong fixture; không publish package công khai.

- **Trust boundary:** npm registry resolution, package-lock integrity và GitHub Actions reference.

- **Điều kiện cần:** nguồn/version không pin hoặc provenance/integrity không được kiểm tra trước build.

- **Môi trường:** npm 10.x, cache/registry loopback, workflow parser local, lifecycle scripts tắt.

Scanner advisory là tín hiệu; bằng chứng phải nối đúng package/version/resolution path với artifact fixture. [S2]

## 6. Cơ chế tấn công

Resolver/build runner lấy dependency hoặc action theo tên/tag/registry có thể thay đổi. Thiếu lock/digest/provenance làm artifact không được review đi vào build và kế thừa quyền CI. [S2]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** tạo project disposable với lockfile/cache và registry 127.0.0.1; chặn outbound.
2. **Baseline:** npm ci --offline tái tạo dependency tree pinned.
3. **Thao tác:** đổi registry/version/action ref trong bản sao fixture rồi so diff lockfile/tree; không chạy lifecycle script.
4. **Expected result:** gate phát hiện nguồn hoặc version không pin; cấu hình sửa chỉ resolve artifact đã khóa.
5. **Boundary:** kiểm tra transitive dependency, lockfile drift và cache miss fail-closed.
6. **Cleanup:** xóa project/cache fixture và dependency-tree.json.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review.

`static-verified` chỉ xác nhận cấu trúc và annotation đã qua gate tĩnh.

Trạng thái này không chứng minh payload hoạt động trên mọi phiên bản.

Trước khi chạy, phải đối chiếu context, điều kiện, encoding, expected result và risk.

Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

### Kiểm tra cấu hình dependency trong lab offline

Lesson không phát hành mã đăng package giả lên public registry, post-install tải shell script hoặc workflow trích xuất secret. Những hành vi đó có thể tác động người dùng thật và không cần thiết để chứng minh root cause. Ví dụ cốt lõi chỉ kiểm tra lockfile, registry và dependency tree của fixture local. [S2]

<!-- payload-id: WEB-A03-SUPPLY-CHAIN-ATTACKS-001 -->
<!-- context: npm 10.x; disposable project with a populated local cache and package-lock.json; secure-build model [S8] -->
<!-- prerequisites: run with outbound network disabled; registry is the local fixture at 127.0.0.1 -->
<!-- encoding: UTF-8 shell source; package-lock.json and dependency-tree.json are UTF-8 JSON generated by npm 10.x -->
<!-- expected-result: npm reports the local registry, npm ci uses the lockfile/cache, and dependency-tree.json records resolved versions -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2 -->
<!-- last-verified: 2026-07-17 -->
```bash
# Inspect the configured source before resolving dependencies
npm config get registry

# Install exactly from the lockfile without lifecycle scripts or network access
npm ci --ignore-scripts --offline
npm ls --all --json > dependency-tree.json
```

## 9. Code dễ bị lỗi và code an toàn

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
      - run: npm install                       # Can rewrite the lockfile/tree during CI
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
      - uses: actions/checkout@<reviewed-full-commit-sha>  # Update through a reviewed bot PR
      - uses: actions/setup-node@<reviewed-full-commit-sha>
        with:
          node-version-file: '.nvmrc'
          registry-url: 'http://127.0.0.1:4873'       # Local registry in this fixture
      - run: npm ci --ignore-scripts           # Fail on package/lock mismatch; use locked tree
      - run: |
          # Verify SLSA provenance of critical dependencies
          slsa-verifier verify-artifact myapp.tar.gz \
            --provenance-path myapp.intoto.jsonl \
            --source-uri github.com/lab-owner/lab-app
```

```ini
# .npmrc - Scoped registry configuration
@lab:registry=http://127.0.0.1:4873/
engine-strict=true
ignore-scripts=true
```

`package-lock.json` khóa cây dependency và chứa trường `integrity` cho artifact, còn `npm ci` từ chối khi `package.json` không khớp lockfile và không tự sửa lockfile. Điều này giúp build lặp lại và phát hiện bytes khác digest đã review; nó không tự chứng minh publisher đáng tin hoặc artifact có provenance đúng, nên registry policy và provenance verification vẫn là kiểm soát riêng. [S6], [S7]

## 10. Phát hiện

- Tái tạo build trong fixture, ghi resolved artifact/digest và so sánh với lock/provenance mong đợi. [S8]

- Review nguồn dependency, CI credential, mutable ref và quyền chạy lifecycle script. [S8]

- Lưu SBOM/provenance/build log đã redaction; không chạy package không tin cậy ngoài sandbox.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Xác định nguồn tin cậy, pin artifact/digest và xác minh provenance trước build/deploy. [S8]

- Bảo vệ CI identity, secret và quyền publish theo least privilege. [S8]

### Defense-in-depth

- SCA/SBOM hỗ trợ inventory và triage, không chứng minh artifact vô hại.

- Cô lập build và giới hạn outbound network/lifecycle script.

## 12. Retest

- **Positive:** build dùng đúng registry, lockfile và artifact digest được duyệt.

- **Negative:** digest/publisher/provenance sai làm pipeline fail closed.

- **Boundary:** transitive dependency, mutable tag, cache cũ và multi-registry.

- **Telemetry:** đối chiếu build attestation, dependency tree và deploy digest.

## 13. Sai lầm thường gặp

- Chỉ pin version trong manifest mà không khóa transitive graph.

- Tin tên package hoặc TLS registry là provenance.

- Cho CI token quyền publish/deploy quá rộng.

- Chạy lifecycle script không tin cậy trên runner có secret.

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

- **Software supply chain:** thành phần, công cụ, dịch vụ và quy trình tạo/phân phối phần mềm. [S8]

- **Provenance:** thông tin về nguồn gốc và các bước tạo ra artifact. [S8]

- **Trust boundary:** điểm chuyển giao quyền hoặc artifact giữa source, CI, registry và deployment. [S8]

## 16. Bài liên quan và đọc thêm

- [Malvertising](../malvertising/) — Xem thêm bài học về Malvertising.

## 17. Tài liệu tham khảo

- **[S2]** SLSA Framework. https://slsa.dev/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S6]** npm CLI 10 documentation — package-lock.json. https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json/ — phiên bản: npm 10; truy cập: 2026-07-17.
- **[S7]** npm CLI 10 documentation — npm ci. https://docs.npmjs.com/cli/v10/commands/npm-ci/ — phiên bản: npm 10; truy cập: 2026-07-17.
- **[S8]** NIST SP 800-218 — Secure Software Development Framework 1.1. https://csrc.nist.gov/pubs/sp/800/218/final — phiên bản: 1.1; truy cập: 2026-07-18.
