// Copyright 2026 ChronoVault Lab
// Licensed under the Apache License, Version 2.0.

///| Parameter constraint kinds supported by deterministic tool contracts.
pub enum FieldKind {
  AnyText
  IntRange(Int, Int)
  EnumAllowlist(Array[String])
  SafePath
  SafeCommandArg
} derive(Show, Eq)

///| Schema rule for a single tool parameter.
pub struct FieldRule {
  name : String
  required : Bool
  kind : FieldKind
} derive(Show, Eq)

///| Complete contract specification for an AI Agent tool.
pub struct ToolContract {
  tool_name : String
  requires_approval : Bool
  rules : Array[FieldRule]
} derive(Show, Eq)

///| Typed parameter value supplied in a tool invocation payload.
pub enum ParamVal {
  Str(String)
  IntNum(Int)
} derive(Show, Eq)

///| Key-value argument entry passed to a tool invocation.
pub struct ParamEntry {
  key : String
  value : ParamVal
} derive(Show, Eq)

///| Structured contract violation reasons.
pub enum Violation {
  MissingRequiredField(String)
  TypeMismatch(String)
  IntOutOfRange(String, Int, Int, Int)
  InvalidEnumValue(String, String)
  PathTraversalBlocked(String, String)
  CommandMetacharBlocked(String, String)
} derive(Show, Eq)

///| Deterministic lifecycle states for a guarded tool invocation.
pub enum ExecState {
  Idle
  Validated
  WaitingApproval
  Approved
  Completed
  Rejected
  Halted
} derive(Show, Eq)

///| Immutable audit trail record emitted at every state transition.
pub struct AuditEvent {
  seq : Int
  from_state : ExecState
  to_state : ExecState
  tool_name : String
  reason : String
} derive(Show, Eq)

///| Step-quota and consecutive-failure circuit breaker.
pub struct BudgetBreaker {
  max_steps : Int
  steps_used : Int
  max_consecutive_failures : Int
  consecutive_failures : Int
  tripped : Bool
  trip_reason : String
} derive(Show, Eq)

///| Immutable snapshot of a guarded agent execution session.
pub struct GuardSession {
  tool_name : String
  requires_approval : Bool
  state : ExecState
  violations : Array[Violation]
  audit_log : Array[AuditEvent]
  breaker : BudgetBreaker
} derive(Show, Eq)

///| Construct a new FieldRule.
pub fn new_field_rule(
  name : String,
  required : Bool,
  kind : FieldKind
) -> FieldRule {
  { name, required, kind }
}

///| Construct a new ToolContract.
pub fn new_tool_contract(
  tool_name : String,
  requires_approval : Bool,
  rules : Array[FieldRule]
) -> ToolContract {
  { tool_name, requires_approval, rules }
}

///| Construct a string ParamEntry.
pub fn str_param(key : String, text : String) -> ParamEntry {
  { key, value: Str(text) }
}

///| Construct an integer ParamEntry.
pub fn int_param(key : String, num : Int) -> ParamEntry {
  { key, value: IntNum(num) }
}

///| Construct a new BudgetBreaker with explicit quotas.
pub fn new_budget_breaker(
  max_steps : Int,
  max_consecutive_failures : Int
) -> BudgetBreaker {
  let tripped = max_steps <= 0 || max_consecutive_failures <= 0
  let trip_reason = if max_steps <= 0 {
    "invalid_max_steps"
  } else if max_consecutive_failures <= 0 {
    "invalid_max_consecutive_failures"
  } else {
    ""
  }
  {
    max_steps,
    steps_used: 0,
    max_consecutive_failures,
    consecutive_failures: 0,
    tripped,
    trip_reason,
  }
}

///| Detect path traversal (`..`) or null-byte injection in file paths.
pub fn has_path_traversal(path : String) -> Bool {
  let mut prev_dot = false
  for ch in path {
    if ch == '\u0000' {
      return true
    }
    if ch == '.' {
      if prev_dot {
        return true
      }
      prev_dot = true
    } else {
      prev_dot = false
    }
  }
  false
}

///| Detect dangerous shell metacharacters in command arguments.
pub fn has_shell_metachar(input : String) -> Bool {
  for ch in input {
    if ch == ';' ||
      ch == '|' ||
      ch == '&' ||
      ch == '$' ||
      ch == '`' ||
      ch == '>' ||
      ch == '<' ||
      ch == '\n' ||
      ch == '\r' ||
      ch == '\u0000' {
      return true
    }
  }
  false
}

fn find_param(params : Array[ParamEntry], key : String) -> ParamVal? {
  let mut i = 0
  while i < params.length() {
    if params[i].key == key {
      return Some(params[i].value)
    }
    i = i + 1
  }
  None
}

fn string_in_list(target : String, allowed : Array[String]) -> Bool {
  let mut i = 0
  while i < allowed.length() {
    if allowed[i] == target {
      return true
    }
    i = i + 1
  }
  false
}

///| Validate tool arguments against a ToolContract and return all violations.
pub fn validate_call(
  contract : ToolContract,
  params : Array[ParamEntry]
) -> Array[Violation] {
  let violations : Array[Violation] = []
  let mut i = 0
  while i < contract.rules.length() {
    let rule = contract.rules[i]
    match find_param(params, rule.name) {
      None =>
        if rule.required {
          violations.push(MissingRequiredField(rule.name))
        }
      Some(val) =>
        match rule.kind {
          AnyText =>
            match val {
              Str(_) => ()
              IntNum(_) => violations.push(TypeMismatch(rule.name))
            }
          IntRange(min_v, max_v) =>
            match val {
              IntNum(n) =>
                if n < min_v || n > max_v {
                  violations.push(IntOutOfRange(rule.name, n, min_v, max_v))
                }
              Str(_) => violations.push(TypeMismatch(rule.name))
            }
          EnumAllowlist(allowed) =>
            match val {
              Str(s) =>
                if not(string_in_list(s, allowed)) {
                  violations.push(InvalidEnumValue(rule.name, s))
                }
              IntNum(_) => violations.push(TypeMismatch(rule.name))
            }
          SafePath =>
            match val {
              Str(p) =>
                if has_path_traversal(p) {
                  violations.push(PathTraversalBlocked(rule.name, p))
                }
              IntNum(_) => violations.push(TypeMismatch(rule.name))
            }
          SafeCommandArg =>
            match val {
              Str(arg) =>
                if has_shell_metachar(arg) {
                  violations.push(CommandMetacharBlocked(rule.name, arg))
                }
              IntNum(_) => violations.push(TypeMismatch(rule.name))
            }
        }
    }
    i = i + 1
  }
  violations
}

fn append_audit(
  existing : Array[AuditEvent],
  from_state : ExecState,
  to_state : ExecState,
  tool_name : String,
  reason : String
) -> Array[AuditEvent] {
  let next_log : Array[AuditEvent] = []
  let mut i = 0
  while i < existing.length() {
    next_log.push(existing[i])
    i = i + 1
  }
  next_log.push({
    seq: existing.length() + 1,
    from_state,
    to_state,
    tool_name,
    reason,
  })
  next_log
}

///| Record a step outcome in BudgetBreaker and evaluate trip thresholds.
pub fn breaker_record_outcome(
  breaker : BudgetBreaker,
  succeeded : Bool
) -> BudgetBreaker {
  if breaker.tripped {
    return breaker
  }
  let next_steps = breaker.steps_used + 1
  let next_failures = if succeeded {
    0
  } else {
    breaker.consecutive_failures + 1
  }
  if next_failures >= breaker.max_consecutive_failures {
    {
      max_steps: breaker.max_steps,
      steps_used: next_steps,
      max_consecutive_failures: breaker.max_consecutive_failures,
      consecutive_failures: next_failures,
      tripped: true,
      trip_reason: "max_consecutive_failures_reached",
    }
  } else if next_steps >= breaker.max_steps {
    {
      max_steps: breaker.max_steps,
      steps_used: next_steps,
      max_consecutive_failures: breaker.max_consecutive_failures,
      consecutive_failures: next_failures,
      tripped: true,
      trip_reason: "step_budget_exhausted",
    }
  } else {
    {
      max_steps: breaker.max_steps,
      steps_used: next_steps,
      max_consecutive_failures: breaker.max_consecutive_failures,
      consecutive_failures: next_failures,
      tripped: false,
      trip_reason: "",
    }
  }
}

///| Start a fresh Idle session bound to an existing BudgetBreaker and audit history.
pub fn new_session(
  contract : ToolContract,
  breaker : BudgetBreaker
) -> GuardSession {
  if breaker.tripped {
    let halted_log = append_audit(
      [],
      Idle,
      Halted,
      contract.tool_name,
      "breaker_already_tripped:" + breaker.trip_reason,
    )
    {
      tool_name: contract.tool_name,
      requires_approval: contract.requires_approval,
      state: Halted,
      violations: [],
      audit_log: halted_log,
      breaker,
    }
  } else {
    {
      tool_name: contract.tool_name,
      requires_approval: contract.requires_approval,
      state: Idle,
      violations: [],
      audit_log: [],
      breaker,
    }
  }
}

///| Transition Idle -> Validated (or Rejected/Halted on contract violation).
pub fn submit_for_validation(
  session : GuardSession,
  contract : ToolContract,
  params : Array[ParamEntry]
) -> GuardSession {
  if session.breaker.tripped {
    let log = append_audit(
      session.audit_log,
      session.state,
      Halted,
      session.tool_name,
      "circuit_breaker_open:" + session.breaker.trip_reason,
    )
    return {
      tool_name: session.tool_name,
      requires_approval: session.requires_approval,
      state: Halted,
      violations: session.violations,
      audit_log: log,
      breaker: session.breaker,
    }
  }
  if session.state != Idle {
    let log = append_audit(
      session.audit_log,
      session.state,
      Halted,
      session.tool_name,
      "illegal_transition_validate_requires_idle",
    )
    return {
      tool_name: session.tool_name,
      requires_approval: session.requires_approval,
      state: Halted,
      violations: session.violations,
      audit_log: log,
      breaker: session.breaker,
    }
  }
  let found = validate_call(contract, params)
  if found.length() > 0 {
    let next_breaker = breaker_record_outcome(session.breaker, false)
    let next_state = if next_breaker.tripped { Halted } else { Rejected }
    let reason = if next_breaker.tripped {
      "contract_violation_halted:" + next_breaker.trip_reason
    } else {
      "contract_violation_rejected"
    }
    let log = append_audit(
      session.audit_log,
      Idle,
      next_state,
      session.tool_name,
      reason,
    )
    {
      tool_name: session.tool_name,
      requires_approval: session.requires_approval,
      state: next_state,
      violations: found,
      audit_log: log,
      breaker: next_breaker,
    }
  } else {
    let log = append_audit(
      session.audit_log,
      Idle,
      Validated,
      session.tool_name,
      "contract_validated",
    )
    {
      tool_name: session.tool_name,
      requires_approval: session.requires_approval,
      state: Validated,
      violations: [],
      audit_log: log,
      breaker: session.breaker,
    }
  }
}

///| Transition Validated -> WaitingApproval (or Approved if contract requires_approval is false).
pub fn gate_approval(session : GuardSession) -> GuardSession {
  if session.state != Validated {
    let log = append_audit(
      session.audit_log,
      session.state,
      Halted,
      session.tool_name,
      "illegal_transition_gate_requires_validated",
    )
    return {
      tool_name: session.tool_name,
      requires_approval: session.requires_approval,
      state: Halted,
      violations: session.violations,
      audit_log: log,
      breaker: session.breaker,
    }
  }
  if session.requires_approval {
    let log = append_audit(
      session.audit_log,
      Validated,
      WaitingApproval,
      session.tool_name,
      "awaiting_human_approval",
    )
    {
      tool_name: session.tool_name,
      requires_approval: session.requires_approval,
      state: WaitingApproval,
      violations: session.violations,
      audit_log: log,
      breaker: session.breaker,
    }
  } else {
    let log = append_audit(
      session.audit_log,
      Validated,
      Approved,
      session.tool_name,
      "low_risk_auto_approved",
    )
    {
      tool_name: session.tool_name,
      requires_approval: session.requires_approval,
      state: Approved,
      violations: session.violations,
      audit_log: log,
      breaker: session.breaker,
    }
  }
}

///| Resolve human-in-the-loop review: WaitingApproval -> Approved | Rejected (or Halted if breaker trips).
pub fn resolve_approval(
  session : GuardSession,
  approved : Bool,
  reviewer_note : String
) -> GuardSession {
  if session.state != WaitingApproval {
    let log = append_audit(
      session.audit_log,
      session.state,
      Halted,
      session.tool_name,
      "illegal_transition_resolve_requires_waiting_approval",
    )
    return {
      tool_name: session.tool_name,
      requires_approval: session.requires_approval,
      state: Halted,
      violations: session.violations,
      audit_log: log,
      breaker: session.breaker,
    }
  }
  if approved {
    let log = append_audit(
      session.audit_log,
      WaitingApproval,
      Approved,
      session.tool_name,
      "approved:" + reviewer_note,
    )
    {
      tool_name: session.tool_name,
      requires_approval: session.requires_approval,
      state: Approved,
      violations: session.violations,
      audit_log: log,
      breaker: session.breaker,
    }
  } else {
    let next_breaker = breaker_record_outcome(session.breaker, false)
    let target = if next_breaker.tripped { Halted } else { Rejected }
    let log = append_audit(
      session.audit_log,
      WaitingApproval,
      target,
      session.tool_name,
      "rejected:" + reviewer_note,
    )
    {
      tool_name: session.tool_name,
      requires_approval: session.requires_approval,
      state: target,
      violations: session.violations,
      audit_log: log,
      breaker: next_breaker,
    }
  }
}

///| Finalize execution from Approved -> Completed (or Rejected/Halted on tool error or illegal bypass).
pub fn finalize_execution(
  session : GuardSession,
  tool_succeeded : Bool,
  summary : String
) -> GuardSession {
  if session.state != Approved {
    let log = append_audit(
      session.audit_log,
      session.state,
      Halted,
      session.tool_name,
      "illegal_bypass_execution_requires_approved",
    )
    return {
      tool_name: session.tool_name,
      requires_approval: session.requires_approval,
      state: Halted,
      violations: session.violations,
      audit_log: log,
      breaker: session.breaker,
    }
  }
  if session.breaker.steps_used >= session.breaker.max_steps {
    let tripped_breaker : BudgetBreaker = {
      max_steps: session.breaker.max_steps,
      steps_used: session.breaker.steps_used,
      max_consecutive_failures: session.breaker.max_consecutive_failures,
      consecutive_failures: session.breaker.consecutive_failures,
      tripped: true,
      trip_reason: "step_budget_exhausted",
    }
    let log = append_audit(
      session.audit_log,
      Approved,
      Halted,
      session.tool_name,
      "halted_step_budget_exhausted",
    )
    return {
      tool_name: session.tool_name,
      requires_approval: session.requires_approval,
      state: Halted,
      violations: session.violations,
      audit_log: log,
      breaker: tripped_breaker,
    }
  }
  let next_breaker = breaker_record_outcome(session.breaker, tool_succeeded)
  if tool_succeeded {
    let log = append_audit(
      session.audit_log,
      Approved,
      Completed,
      session.tool_name,
      "completed:" + summary,
    )
    {
      tool_name: session.tool_name,
      requires_approval: session.requires_approval,
      state: Completed,
      violations: session.violations,
      audit_log: log,
      breaker: next_breaker,
    }
  } else {
    let target = if next_breaker.tripped { Halted } else { Rejected }
    let log = append_audit(
      session.audit_log,
      Approved,
      target,
      session.tool_name,
      "execution_failed:" + summary,
    )
    {
      tool_name: session.tool_name,
      requires_approval: session.requires_approval,
      state: target,
      violations: session.violations,
      audit_log: log,
      breaker: next_breaker,
    }
  }
}
