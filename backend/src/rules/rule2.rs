//! Rule 2: Track operating modes.

use crate::ast::*;
use super::{RuleResult, Violation, utils::expr_text};

pub fn check(program: &Program) -> RuleResult {
    let mut has_mode = false;
    let mut first_fn_line = 0usize;

    for f in &program.functions {
        if first_fn_line == 0 { first_fn_line = f.line; }
        for st in &f.statements {
            match st {
                Statement::Assign { target, .. } => {
                    if let Expression::Identifier(name) = target {
                        let n = name.to_ascii_uppercase();
                        if n.contains("MODE") || n.contains("AUTO") || n.contains("MANUAL") || n.contains("RUNSTATE") {
                            has_mode = true; break;
                        }
                    }
                }
                Statement::IfStmt { condition, .. } => {
                    if condition_uses_mode_var(condition) {
                        has_mode = true; break;
                    }
                }
                 Statement::CaseStmt { expression, .. } => {
                    let c = expr_text(expression).to_ascii_uppercase();
                    // A CASE statement on a variable with "STATE" or "STEP" is a state machine.
                    if c.contains("MODE") || c.contains("STATE") || c.contains("STEP") {
                        has_mode = true; break; // This break is for the inner loop
                    }
                }
                _ => {}
            }
        }
        if has_mode { break; }
    }

    if has_mode {
        RuleResult::ok(2, "Track operating modes")
    } else {
        RuleResult::violations(vec![Violation{
            rule_no: 2,
            rule_name: "Track operating modes".into(),
            line: first_fn_line, // fallback (Program has no .line)
            reason: "No state machine or explicit mode-tracking variable found.".into(),
            suggestion: "Implement a CASE state machine or guard logic on CPU_MODE/Mode/RunState.".into()
        }])
    }
}

/// Recursively check an expression to see if it references a mode-related variable.
/// This is more robust than converting the expression to text and searching.
fn condition_uses_mode_var(e: &Expression) -> bool {
    match e {
        Expression::Identifier(s) => {
            let up = s.trim().to_ascii_uppercase();
            up.contains("CPU_MODE") || up.contains("MODE") || up.contains("RUNSTATE") // Check for mode-related keywords
        }
        Expression::UnaryOp { expr, .. } => condition_uses_mode_var(expr),
        Expression::BinaryOp { left, right, .. } => {
            condition_uses_mode_var(left) || condition_uses_mode_var(right)
        }
        Expression::Index { base, index, .. } => condition_uses_mode_var(base) || condition_uses_mode_var(index),
        Expression::FuncCall { args, .. } => args.iter().any(condition_uses_mode_var),
        _ => false,
    }
}