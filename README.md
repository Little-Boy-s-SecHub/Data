# SecHub Data — Web & Application Security Curriculum

<p align="center">
  <strong>📚 83 lessons · 11 OWASP categories · English & Vietnamese</strong>
</p>

> The central knowledge base for the [SecHub Learning Platform](https://sechub-academy.vercel.app/). Contains all theoretical lessons, vulnerability write-ups, and cheat sheets powering the platform's learning materials.

> [!WARNING]
> Only practice payloads in a local lab or on systems where you have **explicit written authorization**. Always cross-check the context, version, and safety conditions noted in each lesson.

---

## 📖 Content Structure

Content is organized by language and vulnerability category, following the OWASP classification:

```
Data/
├── eng/                                    # 🇬🇧 English Content
│   ├── 01-broken-access-control/
│   ├── 02-security-misconfiguration/
│   ├── 03-supply-chain/
│   ├── 04-cryptographic-failures/
│   ├── 05-injection/
│   ├── 06-insecure-design/
│   ├── 07-authentication-failures/
│   ├── 08-data-integrity-failures/
│   ├── 09-logging-alerting/
│   ├── 10-exceptional-conditions/
│   ├── 11-api-security/
│   ├── README.md
│   └── security_cheatsheet.md              # Consolidated cheat sheet
│
└── vietnam/                                # 🇻🇳 Vietnamese Content
    ├── 01-broken-access-control/
    ├── ...same structure as eng...
    ├── README.md
    └── security_cheatsheet.md
```

### Vulnerability Categories

| # | Category | Focus Areas |
|---|---|---|
| 01 | **Broken Access Control** | IDOR, privilege escalation, path traversal |
| 02 | **Security Misconfiguration** | Default creds, verbose errors, open cloud storage |
| 03 | **Supply Chain** | Dependency confusion, typosquatting, compromised packages |
| 04 | **Cryptographic Failures** | Weak algorithms, key management, insecure transport |
| 05 | **Injection** | SQL injection, command injection, LDAP injection |
| 06 | **Insecure Design** | Business logic flaws, missing rate limits, trust boundaries |
| 07 | **Authentication Failures** | Brute force, credential stuffing, session fixation |
| 08 | **Data Integrity Failures** | Insecure deserialization, unsigned updates |
| 09 | **Logging & Alerting** | Insufficient logging, log injection, monitoring gaps |
| 10 | **Exceptional Conditions** | Unhandled exceptions, error-based info disclosure |
| 11 | **API Security** | BOLA, BFLA, mass assignment, rate limiting |

---

## 🔄 How This Repo Powers the Platform

```
This Repository (Data/)            SecHub Backend
┌─────────────────────┐           ┌──────────────────┐
│  Markdown lessons   │──sync──▶  │ SyncController   │
│  updated via PR     │           │ GithubLessonData │
│                     │           │ Service           │
└─────────────────────┘           └────────┬─────────┘
                                           │
                                           ▼
                                  ┌──────────────────┐
                                  │   PostgreSQL DB   │
                                  │  (lessons table)  │
                                  └────────┬─────────┘
                                           │
                                           ▼
                                  ┌──────────────────┐
                                  │   Frontend UI     │
                                  │  /learning page   │
                                  └──────────────────┘
```

The SecHub backend's `SyncController` and `GithubLessonDataService` periodically pull from the `main` branch of this repository. When you merge a PR that adds or updates a lesson here, the changes automatically propagate to the live platform's database — **no backend redeployment needed**.

---

## 📝 Lesson Format

Each lesson follows a consistent pedagogical structure:

```markdown
# Lesson Title

## Objective
What the learner will understand after this lesson.

## Foundation
Core concepts and background knowledge.

## Root Cause
Why this vulnerability exists at a technical level.

## Attack Mechanism
How the vulnerability is exploited, with annotated code examples.

## Lab Conditions
Specific environment, versions, and setup for safe practice.

## Defense Controls
How to prevent/mitigate, with secure code examples.

## Retest
How to verify the fix actually works.

## References
Cited technical sources (CVEs, RFCs, official docs).
```

---

## ✍️ Contributing

We welcome contributions from security researchers and educators!

### Guidelines

1. **Markdown only** — All lessons must be `.md` files.
2. **Follow the structure** — Use the lesson format template above.
3. **Both languages** — If you add a lesson in `eng/`, please also provide the Vietnamese version in `vietnam/` (or vice versa). Partial translations are accepted.
4. **Cite your sources** — Attach reference links for all technical claims.
5. **Payload safety** — Every payload must include context, conditions, encoding, expected result, and risk level.
6. **No real targets** — All examples must use localhost, lab environments, or fictional targets.

### Quick Start

```bash
git clone https://github.com/Little-Boy-s-SecHub/Data.git
cd Data

# Create a new lesson
mkdir -p eng/05-injection/new-lesson
echo "# New Injection Lesson" > eng/05-injection/new-lesson/README.md

# Submit a PR
git checkout -b lesson/new-injection-technique
git add .
git commit -m "Add lesson: new injection technique"
git push origin lesson/new-injection-technique
```

---

## 📊 Content Quality Standards

| Criterion | Requirement |
|---|---|
| **Root cause clarity** | Each lesson must clearly separate root cause from attack mechanism |
| **Source attribution** | Technical claims require reference links |
| **Payload documentation** | Context, conditions, encoding, expected result, risk level |
| **Defense parity** | Every attack technique must have a corresponding defense section |
| **Retest guidance** | Instructions on how to verify the fix works |

---

## 🔗 Related Repositories

| Repository | Purpose |
|---|---|
| [`SecHub`](https://github.com/Little-Boy-s-SecHub/SecHub) | Application code (frontend + backend + lab orchestration) |
| [`.github`](https://github.com/Little-Boy-s-SecHub/.github) | Organization profile & architecture overview |
