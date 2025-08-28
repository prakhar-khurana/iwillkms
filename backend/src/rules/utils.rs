//! Shared utility functions for rule implementations.
//! - Lightweight expression stringifier (expr_text)
//! - Sensitive-source heuristic (is_sensitive_variable)
//! - Optional annotation/guard indices (has_plausibility_annotation_above, current_guard_text)
//! - Small predicates reused across multiple rules

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::ast::{BinOp, Expression, Statement, UnaryOp};

/// Heuristic for sensitive (HMI/recipe/config) variables.
/// Consider making this policy-driven later.
pub fn is_sensitive_variable(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    // Typical sources: HMI tags, recipe/config parameters, DB parameter conventions
    upper.contains("HMI") || upper.contains("RECIPE") || upper.contains(".PAR.")
}

/// Stringify an expression for simple textual reasoning in rules.
/// (Keeps formatting stable and compact.)
pub fn expr_text(e: &Expression) -> String {
    match e {
        Expression::NumberLiteral(n, _) => n.to_string(),
        Expression::BoolLiteral(b, _) => b.to_string(),
        Expression::VariableRef(v) => v.clone(),
        Expression::Index { base, index, .. } => format!("{}[{}]", expr_text(base), expr_text(index)),
        Expression::UnaryOp { op, expr, .. } => match op {
            UnaryOp::Not => format!("NOT {}", expr_text(expr)),
        },
        Expression::BinaryOp { op, left, right, .. } => {
            let o = match op {
                BinOp::Add => "+",
                BinOp::Sub => "-",
                BinOp::Mul => "*",
                BinOp::Div => "/",
                BinOp::Eq  => "=",
                BinOp::Neq => "<>",
                BinOp::Lt  => "<",
                BinOp::Le  => "<=",
                BinOp::Gt  => ">",
                BinOp::Ge  => ">=",
                BinOp::And => "AND",
                BinOp::Or  => "OR",
            };
            format!("({} {} {})", expr_text(left), o, expr_text(right))
        }
        Expression::FuncCall { name, args, .. } => {
            let arg_str = args.iter().map(expr_text).collect::<Vec<_>>().join(", ");
            format!("{}({})", name, arg_str)
        }
    }
}

//
// ---- Optional annotation & guard indices ---------------------------------
// These allow rules to query nearby comments (e.g., @PlausibilityCheck)
// and dominance guards for a given source line.
//
// If you don't populate these indices, the helpers return safe defaults.
//

static COMMENT_INDEX: OnceLock<Vec<(usize, String)>> = OnceLock::new();
static GUARD_MAP: OnceLock<HashMap<usize, String>> = OnceLock::new();

/// Install a (line -> comment) index once per analysis run.
/// Safe to skip; `has_plausibility_annotation_above` will return false without it.
pub fn set_comment_index(index: Vec<(usize, String)>) {
    let _ = COMMENT_INDEX.set(index);
}

/// Install a (line -> guard text) map once per analysis run.
/// Safe to skip; `current_guard_text` will return empty without it.
pub fn set_guard_map(map: HashMap<usize, String>) {
    let _ = GUARD_MAP.set(map);
}

/// True if there is a plausibility/validation annotation within `max_gap` lines above `line`.
pub fn has_plausibility_annotation_above(line: usize, max_gap: usize) -> bool {
    const TAGS: &[&str] = &["@PlausibilityCheck", "@Validated"];
    if let Some(comments) = COMMENT_INDEX.get() {
        comments.iter().any(|(l, c)| {
            *l < line
                && line - *l <= max_gap
                && TAGS.iter().any(|t| c.contains(t))
        })
    } else {
        false
    }
}

/// Best-effort guard text dominating `line`.
/// If a precise per-line entry is installed via `set_guard_map`, return it.
/// Otherwise return empty (caller may fall back to an accumulated guard stack).
pub fn current_guard_text(line: usize) -> String {
    if let Some(map) = GUARD_MAP.get() {
        if let Some(s) = map.get(&line) {
            return s.clone();
        }
    }
    String::new()
}

//
// ---- Small predicates reused across rules --------------------------------
//

/// True if a statement clearly assigns/raises an alarm/diagnostic.
pub fn is_alarm_assignment(s: &Statement) -> bool {
    match s {
        Statement::Assign { target, value, .. } => {
            let t = target.name.to_ascii_uppercase();
            let v = expr_text(value).to_ascii_uppercase();
            t.contains("ALARM") || t.contains("DIAG") || t.contains("FAULT") || v.contains("LOG")
        }
        Statement::Call { name, .. } => {
            let n = name.to_ascii_uppercase();
            n.contains("ALARM") || n.contains("DIAG") || n.contains("LOG")
        }
        _ => false
    }
}

/// Name heuristic for “critical outputs” used by Rule 15 when policy isn’t available.
pub fn looks_like_critical_output(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    n.contains("CRITICAL")
        || n.contains("SAFE")
        || n.ends_with("_OUT")
        || n.contains("MOTOR")
        || n.contains("OUTPUT")
}

/// True if expression is an explicit FALSE / 0 (safe default), used in Rule 15.
pub fn is_zero_or_false(e: &Expression) -> bool {
    matches!(e, Expression::BoolLiteral(false, _) | Expression::NumberLiteral(0, _))
}

/// Convenience: stringify assignment if the statement is an assignment; else "".
/// (Handy for coarse-grained pattern checks in rules 16–20.)
pub fn expr_text_of_assign(s: &Statement) -> String {
    if let Statement::Assign { target, value, .. } = s {
        format!("{} := {}", target.name, expr_text(value))
    } else {
        String::new()
    }
}

//
// ---- Optional coarse-grained helpers for operational rules ----------------
// (Not strictly required by all rules, but used by some versions.)
//

/// True if a statement captures OB1_PREV_CYCLE (Rule 16).
pub fn is_cycle_capture(s: &Statement) -> bool {
    expr_text_of_assign(s).to_ascii_uppercase().contains("OB1_PREV_CYCLE")
}

/// True if a statement aggregates cycle stats (avg/max/etc.) (Rule 16).
pub fn is_cycle_aggregate(s: &Statement) -> bool {
    let up = expr_text_of_assign(s).to_ascii_uppercase();
    up.contains("AVG") || up.contains("AVERAGE") || up.contains("MAX") || up.contains("MIN")
}

/// True if a statement emits cycle stats to HMI/DB/LOG (Rule 16).
pub fn is_cycle_emit(s: &Statement) -> bool {
    let up = expr_text_of_assign(s).to_ascii_uppercase();
    up.contains("HMI") || up.contains("DB") || up.contains("LOG")
}

/// True if a statement increments an UPTIME counter monotonically (Rule 17).
pub fn is_monotonic_uptime_increment(s: &Statement) -> bool {
    let up = expr_text_of_assign(s).to_ascii_uppercase();
    up.contains("UPTIME") && up.contains(":=") && (up.contains("+1") || up.contains("+ 1"))
}

/// True if a statement logs/stores the uptime value (Rule 17).
pub fn is_log_or_store_uptime(s: &Statement) -> bool {
    let up = expr_text_of_assign(s).to_ascii_uppercase();
    up.contains("UPTIME") && (up.contains("HMI") || up.contains("DB") || up.contains("LOG"))
}

/// True if a statement reads memory status/areas (Rule 19).
pub fn is_memory_status_read(s: &Statement) -> bool {
    let up = expr_text_of_assign(s).to_ascii_uppercase();
    // Coarse: SFC24/TEST_DB or direct %MW/%DB/%M reads showing up in expressions
    up.contains("SFC24") || up.contains("TEST_DB") || up.contains("%MW") || up.contains("%DB") || up.contains("%M")
}

/// True if a statement performs a threshold comparison (Rule 19).
pub fn is_threshold_compare(s: &Statement) -> bool {
    match s {
        Statement::IfStmt { condition, .. } => {
            let c = expr_text(condition).to_ascii_uppercase();
            (c.contains(">") || c.contains("<") || c.contains(">=") || c.contains("<="))
                && (c.contains("SFC24") || c.contains("TEST_DB") || c.contains("MEM") || c.contains("%MW") || c.contains("%DB"))
        }
        _ => false,
    }
}

/// True if a statement logs or raises alarm (Rule 19/20).
pub fn is_log_or_alarm(s: &Statement) -> bool {
    is_alarm_assignment(s) || expr_text_of_assign(s).to_ascii_uppercase().contains("LOG")
}

/// True if a statement assigns/records diagnostics (Rule 18 helper used elsewhere).
pub fn is_diag_or_alarm_assignment(s: &Statement) -> bool {
    let up = expr_text_of_assign(s).to_ascii_uppercase();
    up.contains("DIAG") || is_alarm_assignment(s)
}

/// Recognize a simple “false alert trap” wrapper (Rule 20) —
//  a conditional mentioning CRITICAL and logging/assigning inside.
pub fn is_false_alert_trap(s: &Statement) -> bool {
    match s {
        Statement::IfStmt { condition, then_branch, else_branch, .. } => {
            let c = expr_text(condition).to_ascii_uppercase();
            if c.contains("CRITICAL") && (then_branch.iter().any(is_log_or_alarm) || else_branch.iter().any(is_log_or_alarm)) {
                return true;
            }
            false
        }
        _ => false,
    }
}
