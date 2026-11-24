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

