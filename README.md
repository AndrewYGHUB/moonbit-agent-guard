# moonbit-agent-guard

> **Deterministic Tool-Call Contract Validator, Human-in-the-Loop Approval State Machine, and Budget Circuit Breaker for AI Agents in Pure MoonBit.**  
> Developed by **ChronoVault Lab** · Licensed under **Apache-2.0**

---

## Why `moonbit-agent-guard`?

Modern LLM Agents invoke file-system, deployment, and shell-adjacent tools where probabilistic prompt instructions alone cannot guarantee safety:

1. **Hallucinated or Malicious Arguments**: Unchecked `../../etc/passwd` path traversals, out-of-bounds replica counts, unauthorized target environments, or `; curl ... | sh` shell metacharacter injections.
2. **Skipped Human Approval Gates**: High-impact mutations executed without passing through an explicit `WaitingApproval -> Approved` transition.
3. **Runaway Retry Loops**: Infinite tool-call retries exhausting token and compute budgets when an upstream service or schema check repeatedly fails.

`moonbit-agent-guard` embeds a **zero-dependency, algebraic-data-type (ADT) safety kernel** compiled via MoonBit (targeting WebAssembly, JS, or Native) directly between the LLM planner and tool executors.

---

## Core Architecture

```text
Tool Invocation Payload
        │
        ▼
┌────────────────────────────────────────────────────────┐
│ 1. Contract Validator (validate_call)                  │
│    - Required fields, IntRange(min, max), EnumAllowlist│
│    - SafePath (`..` & NUL block), SafeCommandArg       │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 2. Deterministic Approval State Machine                │
│    Idle -> Validated -> WaitingApproval -> Approved    │
│                                         └─> Completed  │
│    Illegal bypass / violation -> Rejected | Halted     │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 3. BudgetBreaker & Immutable Audit Trail               │
│    - max_steps & max_consecutive_failures enforcement  │
│    - Copy-on-transition AuditEvent sequence log        │
└────────────────────────────────────────────────────────┘
```

### State Transition Matrix

| Current State | Operation | Guard Condition | Next State |
| :--- | :--- | :--- | :--- |
| `Idle` | `submit_for_validation` | `violations == []` | `Validated` |
| `Idle` | `submit_for_validation` | `violations != []` (below trip limit) | `Rejected` |
| `Idle` | `submit_for_validation` | `violations != []` (hits failure limit) | `Halted` |
| `Validated` | `gate_approval` | `requires_approval == true` | `WaitingApproval` |
| `Validated` | `gate_approval` | `requires_approval == false` | `Approved` |
| `WaitingApproval` | `resolve_approval(true, ...)` | Reviewer approves | `Approved` |
| `WaitingApproval` | `resolve_approval(false, ...)` | Reviewer rejects | `Rejected` / `Halted` |
| `Approved` | `finalize_execution(true, ...)` | Within `max_steps` | `Completed` |
| Any non-`Approved` | `finalize_execution(...)` | Illegal state bypass attempt | `Halted` |

---

## Repository Layout

```text
moonbit-agent-guard/
├── moon.mod.json          # MoonBit module manifest (chronovault/agent_guard)
├── src/
│   ├── moon.pkg.json      # Package configuration
│   ├── guard.mbt          # Core contract validator, state machine & BudgetBreaker
│   └── guard_test.mbt     # 10 unit & adversarial boundary test suites
├── verify_semantics.py    # 1:1 isomorphic reference verifier & MoonBit syntax checker
├── package_release.py     # Deterministic whitelist release bundler & clean-room tester
├── LICENSE                # Apache-2.0 License
└── README.md
```

---

## Quick Start & Verification

### Run with MoonBit Toolchain

```bash
moon check
moon test
```

### Run Differential Semantics & Static Contract Verification

```bash
python3 verify_semantics.py --self-test
```

### Build Clean-Room Verified Release Archive

```bash
python3 package_release.py --self-test
```
