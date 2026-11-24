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

