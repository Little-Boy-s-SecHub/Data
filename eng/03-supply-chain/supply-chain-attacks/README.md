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
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Supply Chain Attacks (CI/CD Pipeline) by root cause instead of only describing the consequences.
- Identify trust boundaries, assets, actors, and necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Select root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Dependency graph, build pipeline, and artifact provenance.

- Registry resolution, lockfile, and lifecycle script.

- Trust boundary between source, CI runner, registry, and deployment.

## 3. Background Knowledge

Imagine you are building a house. Instead of casting each brick yourself, forging each nail, or making cement from scratch, you go to the building materials store to buy ready-made products to assemble. Your house will be completed very quickly. However, if a malicious person sneaks into the brick factory and mixes explosives into the clay, or swaps steel nails for hollow iron nails, your house, no matter how technically well-built, will face the risk of collapsing. [S8]

The software supply chain consists of source, dependencies, build tools, pipeline, artifacts, and services involved in delivering software to the runtime environment. The proportion of third-party code varies significantly depending on the product, so the lesson does not use a common percentage figure. The root cause needs to specify which trust boundary accepts unapproved, unlocked source/artifacts or those lacking proper provenance/integrity. [S2], [S8]

A typical CI/CD pipeline operates as follows:

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
Each step is a point where an attacker can intervene: from inserting malicious code into a dependency, to compromising GitHub Action, or changing the base Docker image. [S8]

## 4. Description and Root Cause

The **Supply Chain Attack** vulnerability occurs when an attacker does not try to hack directly into your defense system, but takes a detour by **attacking external components** that you completely trust and use daily. [S8]

This is one of the most dangerous threats today because developers often have a mentality of blindly trusting popular library packages or automated tools. Attackers can use many sophisticated tricks:
- **Dependency Confusion**: Exploiting configuration gaps to trick the server into downloading a malicious library that has the same name as an internal company library but with a version pushed to a very high number in public repositories.
- **Typosquatting**: Registering library packages with misspelled names similar to popular libraries (such as `lodahs` instead of `lodash`) to wait for developers to mistype and download them.
- **Compromised Maintainer**: Hacking the account of a maintainer of a popular library to secretly insert malicious code into the next update.
- **CI/CD Poisoning**: Inserting malicious scripts into automated build configurations to steal company passwords and security keys (secrets). [S8]


## 5. Threat Model and Exploitation Conditions

- **Assets:** source, dependency graph, build artifact, and CI secret synthetic.

- **Actor:** maintainer/dependency/CI unreliable action in the fixture; do not publish the package publicly.

- **Trust boundary:** npm registry resolution, package-lock integrity, and GitHub Actions reference.

- **Necessary condition:** source/version without a license or provenance/integrity not checked before build.

- **Environment:** npm 10.x, cache/registry loopback, local workflow parser, lifecycle scripts off.

Scanner advisory is a signal; evidence must correctly connect the package/version/resolution path with the artifact fixture. [S2]

## 6. Attack Mechanism

The resolver/build runner fetching dependencies or actions by name/tag/registry may change. Missing lock/digest/provenance causes artifacts that have not been reviewed to enter the build and inherit CI privileges. [S2]

## 7. Testing in an Authorized Lab

1. **Setup:** create a disposable project with lockfile/cache and registry 127.0.0.1; block outbound.  
2. **Baseline:** npm ci --offline to recreate pinned dependency tree.  
3. **Action:** change registry/version/action ref in the fixture copy then diff lockfile/tree; do not run lifecycle scripts.  
4. **Expected result:** detect unpinned source or version; configuration change only resolves locked artifacts.  
5. **Boundary:** check transitive dependency, lockfile drift, and cache miss fail-closed.  
6. **Cleanup:** delete project/cache fixture and dependency-tree.json.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

### Check dependency configuration in offline lab

Lesson does not release packages with fake registration codes to the public registry, nor download shell scripts or workflows to extract secrets post-install. Such actions can affect real users and are unnecessary to demonstrate the root cause. The core example only checks the lockfile, registry, and dependency tree of the local fixture. [S2]

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

## 9. Vulnerable Code and Secure Code

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
`package-lock.json` locks the dependency tree and contains the field `integrity` for the artifact, while `npm ci` rejects when `package.json` does not match the lockfile and does not automatically fix the lockfile. This helps with repeatable builds and detecting bytes differing from a reviewed digest; it does not automatically prove that the publisher is trustworthy or that the artifact has correct provenance, so registry policy and provenance verification remain separate controls. [S6], [S7]

## 10. Detection

- Rebuild in the fixture, record resolved artifact/digest and compare with the expected lock/provenance. [S8]

- Review dependency sources, CI credential, mutable ref, and permission to run lifecycle script. [S8]

- Save SBOM/provenance/build log has been redacted; do not run untrusted packages outside the sandbox.

## 11. Defense

### Compulsory control

- Identify reliable sources, artifact/digest fingerprints, and verify provenance before build/deploy. [S8]

- Protect CI identity, secrets, and publishing rights according to the least privilege. [S8]

### Defense-in-depth

- SCA/SBOM supports inventory and triage, does not prove the artifact is harmless.

- Isolate the build and limit outbound network/lifecycle script.

## 12. Retest

- **Positive:** build uses the correct registry, lockfile, and approved artifact digest.

- **Negative:** digest/publisher/provenance error causes pipeline to fail closed.

- **Boundary:** transitive dependency, mutable tag, old cache, and multi-registry.

- **Telemetry:** cross-check build attestation, dependency tree, and deploy digest.

## 13. Common Mistakes

- Only pin the version in the manifest without locking the transitive graph.

- The package name or TLS registry is provenance.

- The CI token has too broad publish/deploy permissions.

- Running an untrusted lifecycle script on a runner with a secret.

## 14. Summary and Checklist

- [ ] Root cause, consequences, and exploitation techniques have been separated.  
- [ ] Actor, role/authentication, trust boundary, technology, and version are clear.  
- [ ] Payload has a unique ID, context, encoding, conditions, expected result, risk, validation, and source.  
- [ ] Code prone to errors/unsafe uses the same framework, version, and use case.  
- [ ] Mandatory controls cannot be replaced with defense-in-depth.  
- [ ] Positive, negative, boundary cases, and telemetry have been retested.  
- [ ] Sensitive technical claims have references in section 17, and all links are only in sections 16–17.  
- [ ] Cleanup completed; no secrets, real targets, Internet callbacks, or customer data remain.

## 15. Glossary

- **Software supply chain:** components, tools, services, and processes for creating/distributing software. [S8]

- **Provenance:** information about the origin and the steps to create the artifact. [S8]

- **Trust boundary:** point of transfer of authority or artifact between source, CI, registry, and deployment. [S8]

## 16. Related Lessons and Further Reading

- [Malvertising](../malvertising/) — See more lessons about Malvertising.

## 17. References

- **[S2]** SLSA Framework. https://slsa.dev/ — version/status: current version; access: 2026-07-17.
- **[S6]** npm CLI 10 documentation — package-lock.json. https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json/ — version: npm 10; access: 2026-07-17.
- **[S7]** npm CLI 10 documentation — npm ci. https://docs.npmjs.com/cli/v10/commands/npm-ci/ — version: npm 10; access: 2026-07-17.
- **[S8]** NIST SP 800-218 — Secure Software Development Framework 1.1. https://csrc.nist.gov/pubs/sp/800/218/final — version: 1.1; access: 2026-07-18.