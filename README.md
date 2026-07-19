# SecHub Data

Security learning content for the [SecHub platform](https://sechub-academy.vercel.app/). Contains lessons in English and Vietnamese across 11 OWASP vulnerability categories.

## Structure

```
Data/
├── eng/
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
│   └── security_cheatsheet.md
│
└── vietnam/
    ├── (same structure as eng/)
    └── security_cheatsheet.md
```

## How to Add a Lesson

1. Create a `.md` file under the appropriate category folder in `eng/` and/or `vietnam/`.
2. Follow the lesson format:

```markdown
# Lesson Title

## Objective
## Foundation
## Root Cause
## Attack Mechanism
## Lab Conditions
## Defense Controls
## Retest
## References
```

3. Open a pull request targeting `main`. Once merged, the SecHub backend will automatically sync the new content to the platform — no redeployment needed.

> [!WARNING]
> Only include payloads intended for local labs or authorized environments. Do not reference real targets.
