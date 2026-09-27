# Contributing to Sentry-Grid

Thank you for your interest in contributing to **Sentry-Grid** — the sovereign network compliance and automated verification platform engineered by **Team Cyber Lakshya** for **SIH 2026 (Problem Statement: SIH26155)**.

---

## 🛠️ Code of Conduct & Sovereign Principles

Sentry-Grid is designed for high-assurance, air-gapped critical infrastructure and defense deployments (NTRO / Tri-Services / CERT-In). All contributions must strictly preserve:
1. **Zero External Egress**: No module may invoke external web services, remote LLM APIs, or telemetry beacons.
2. **Deterministic & Formal Correctness**: Critical security policies (ACL reachability, DMZ isolation) must maintain formal verification tests (Z3 SMT solver).
3. **Memory Safety & Performance**: C11 native extensions must use arena allocation with zero memory leaks.

---

## 🚀 Development Workflow

### 1. Prerequisites
- Python 3.10+ (Python 3.12 recommended)
- GCC 13+ / MinGW-w64 (for C11 native lexer)
- Git

### 2. Fork & Local Setup
```bash
git clone https://github.com/team-cyber-lakshya/sentry-grid.git
cd sentry-grid
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Branching Guidelines
Use descriptive branch names:
- `feature/<feature-name>`
- `fix/<bug-description>`
- `docs/<doc-update>`

### 4. Running Tests
Before submitting any pull request, ensure **all 171 tests pass**:
```bash
pytest tests/unit/ -v
```

---

## 📜 Commit Conventions

Follow the Conventional Commits specification:
- `feat(parser): add Arista EOS BGP neighbor tokenization`
- `fix(smt): correct First-Order Logic formula for negated ACL port ranges`
- `docs(readme): update deployment topology`
- `test(ledger): add Ed25519 signature verification test case`

---

## 🔒 Security Vulnerabilities

Please report any security findings according to our [Security Policy](SECURITY.md).
