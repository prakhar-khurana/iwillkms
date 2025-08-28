//! Rule 2: Track operating modes.

use crate::{rules::Violation, rules::RuleResult};
use crate::ast::*;
use super::utils::expr_text;

pub fn check(program: &Program) -> RuleResult {
    let mut has_mode = false;
    let mut first_fn_line = 0usize;

    for f in &program.functions {
        if first_fn_line == 0 { first_fn_line = f.line; }
        for st in &f.statements {
            match st {
                Statement::Assign { target, .. } => {
                    if let Expression::VariableRef(name) = target {
                        let n = name.to_ascii_uppercase();
                        if n.contains("MODE") || n.contains("AUTO") || n.contains("MANUAL") || n.contains("RUNSTATE") {
                            has_mode = true; break;
                        }
                    }
                }
                Statement::IfStmt { condition, .. } => {
                    let c = expr_text(condition).to_ascii_uppercase();
                    if c.contains("CPU_MODE") || c.contains(" MODE ") || c.contains("RUNSTATE") {
                        has_mode = true; break;
                    }
                }
                 Statement::CaseStmt { expression, .. } => {
                    let c = expr_text(expression).to_ascii_uppercase();
                    // A CASE statement on a variable with "STATE" or "STEP" is a state machine.
                    if c.contains("MODE") || c.contains("STATE") || c.contains("STEP") {
                        has_mode = true; break;
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
