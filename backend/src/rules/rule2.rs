//! Rule 2: Track operating modes.
//! Verify that the program tracks different operating modes (AUTO, MANUAL, etc.)
//! and implements proper mode transitions with safety checks.

use crate::ast::{Program, Statement, Expression};
use super::{RuleResult, Violation};

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];

    for f in &program.functions {
        let mut has_mode_tracking = false;
        let mut has_mode_transitions = false;
        
        for st in &f.statements {
            match st {
                Statement::Assign { target, value, line } => {
                    let target_up = target.name.to_ascii_uppercase();
                    if target_up.contains("MODE") || target_up.contains("AUTO") || target_up.contains("MANUAL") {
                        has_mode_tracking = true;
                    }
                }
                Statement::IfStmt { condition, line, .. } => {
                    if condition_checks_mode(condition) {
                        has_mode_transitions = true;
                    }
                }
                _ => {}
            }
        }

        if !has_mode_tracking {
            violations.push(Violation {
                rule_no: 2,
                rule_name: "Track operating modes",
                line: f.line,
                reason: format!("Function '{}' does not track operating modes", f.name),
                suggestion: "Add variables to track AUTO/MANUAL/MAINTENANCE modes.".into(),
            });
        }

        if has_mode_tracking && !has_mode_transitions {
            violations.push(Violation {
                rule_no: 2,
                rule_name: "Track operating modes",
                line: f.line,
                reason: format!("Function '{}' tracks modes but lacks transition logic", f.name),
                suggestion: "Add IF statements to handle mode transitions safely.".into(),
            });
        }
    }

    RuleResult::violations(violations)
}

fn condition_checks_mode(expr: &Expression) -> bool {
    match expr {
        Expression::VariableRef(name) => {
            let up = name.to_ascii_uppercase();
            up.contains("MODE") || up.contains("AUTO") || up.contains("MANUAL")
        }
        Expression::BinaryOp { left, right, .. } => {
            condition_checks_mode(left) || condition_checks_mode(right)
        }
        _ => false,
    }
}