# Agent Security Sandbox 🛡️

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: AST Guarded](https://img.shields.io/badge/Security-AST%20Static%20Audit-red.svg)](https://github.com/pokushko/agent-security-sandbox)
[![Tests: 100% Pass](https://img.shields.io/badge/tests-6%2F6%20passing-brightgreen.svg)](https://github.com/pokushko/agent-security-sandbox)

A production-grade AST inspection and execution containment toolkit for LLM-based autonomous agent loops. Protects host environments against untrusted LLM code mutations, unauthorized system calls, dunder escape exploits, and adversarial prompt injections.

Authored by **Roman Pokushko** ([@pokushko](https://github.com/pokushko)).

```mermaid
flowchart TD
    LLMCode["LLM Agent Proposed Code"] --> ASTGuard["ASTSecurityGuard.validate()"]
    
    subgraph Inspection ["Static AST Syntax Inspection"]
        ASTGuard --> CheckImports{"Imports Allowed? (no os/subprocess/sys)"}
        CheckImports -->|Violation| BlockImport["SecurityViolationError (Line N)"]
        CheckImports -->|Pass| CheckCalls{"Forbidden Calls? (no eval/exec)"}
        CheckCalls -->|Violation| BlockCall["SecurityViolationError (Line N)"]
        CheckCalls -->|Pass| CheckDunder{"Dunder Traversal? (no __class__.__base__)"}
        CheckDunder -->|Violation| BlockDunder["SecurityViolationError (Line N)"]
    end
    
    CheckDunder -->|Clean AST| Executor["SafeCodeExecutor.execute()"]
    Executor --> SandboxedRun["Restricted Global Namespace + Stdout Capture"]
    SandboxedRun --> SafeArtifacts["Verified Output Variables & Execution Artifacts"]
```

---

## ⚡ The Security Problem

When autonomous agents are granted code interpreter tools or dynamic mutation rights (e.g. self-evolving agents, scientific solvers), LLMs can generate:
1. **Accidental Host Damage:** Recursive filesystem deletions (`shutil.rmtree`, `rm -rf`).
2. **Adversarial Prompt Escapes:** Python dunder attribute traversal (`().__class__.__base__.__subclasses__()`) to bypass standard sandbox globals.
3. **Information Exfiltration:** Background socket bindings and network exfiltration via dynamic imports (`__import__('socket')`).

**Agent Security Sandbox** enforces zero-trust pre-flight verification: the code is parsed into Python's Abstract Syntax Tree (AST) and rigorously audited before a single byte is ever passed to the Python interpreter.

---

## 🚀 Key Modules

* **`ASTSecurityGuard`:** Static visitor inspecting import modules, dynamic call identifiers, and dunder traversal chains.
* **`PromptSanitizer`:** Scans incoming user/agent prompts for jailbreak patterns and automatically redacts leaked API keys and tokens.
* **`SafeCodeExecutor`:** Executes verified AST code blocks inside an isolated, stripped namespace with deterministic stdout capturing.

---

## 💻 Quickstart

### Installation

```bash
git clone https://github.com/pokushko/agent-security-sandbox.git
cd agent-security-sandbox
pip install -e .
```

### Usage Example

```python
from security_sandbox import ASTSecurityGuard, SecurityViolationError, SafeCodeExecutor

guard = ASTSecurityGuard()
malicious_code = "import os; os.system('whoami')"

try:
    guard.validate(malicious_code)
except SecurityViolationError as err:
    print(f"Intercepted attack: {err}")

# Safe mathematical calculation
executor = SafeCodeExecutor()
clean_code = """
scores = [0.92, 0.88, 0.95]
avg_score = sum(scores) / len(scores)
"""
result = executor.execute(clean_code)
print("Result:", result["variables"]["avg_score"])
```

---

## 🧪 Verification & Tests

To run the complete validation test suite:

```bash
pytest tests/ -v
```

All 6 test suites verify:
- Forbidden module imports (`os`, `sys`, `subprocess`, `shutil`).
- Dynamic evaluation interception (`eval`, `exec`).
- Dunder traversal escape blocking.
- Prompt injection and jailbreak detection.
- Credential leak redaction (`sk-...`, `ghp_...`).
- Sandboxed computational execution.

---

## 📄 License

MIT License. Free for open research and commercial autonomous agent deployment.
