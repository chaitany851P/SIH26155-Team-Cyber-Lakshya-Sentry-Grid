# Security Policy

## 🛡️ Supported Versions

Sentry-Grid is deployed across sensitive defense and national infrastructure networks. We actively maintain and provide security patches for the following versions:

| Version | Supported |
| :--- | :--- |
| `2.4.x` (Latest NTRO Edition) | :white_check_mark: |
| `< 2.4.0` | :x: |

---

## 🔒 Reporting a Vulnerability

Because Sentry-Grid is designed for high-assurance, air-gapped sovereign environments (NTRO, CERT-In, Indian Armed Forces), we treat all security reports with high urgency.

### How to Report:
1. **Do not open a public GitHub issue** for undisclosed vulnerabilities.
2. Send an encrypted or confidential report to **Team Cyber Lakshya** via the official SIH portal or designated team lead contact.
3. Include:
   - Vulnerability classification (e.g., SMT Logic Bypass, AST Buffer Overflow, Cryptographic Ledger Inconsistency).
   - Exact steps to reproduce, including sample configuration file.
   - Proof-of-concept (PoC) script or minimal reproducible example.

---

## 🏛️ Air-Gapped High-Assurance Guarantees

- **Zero Network Egress**: Sentry-Grid contains zero analytics beacons, telemetry calls, or cloud dependencies.
- **Formally Verified Policies**: Security rule evaluations are mathematically verified using the Microsoft Research Z3 SMT Theorem Prover.
- **Cryptographic Immutability**: All audit states are permanently sealed into an append-only SHA-512 Merkle block chain.
