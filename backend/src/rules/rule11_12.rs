//! Rules 11 & 12: Plausibility checks.
//! Requirement: Any use of an HMI-accessible DB variable must be immediately
//! preceded by a comment block starting with "(* @PlausibilityCheck:".

use crate::ast::{Expression, Program, Statement};
use super::{RuleResult, Violation};

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];

    for f in &program.functions {
        let mut prev_was_plaus = false;
        for st in &f.statements {
            let mut check_expr = None;
            let mut line = 0;

            match st {
                Statement::Comment { text, .. } => {
                    prev_was_plaus = text.trim().starts_with("(* @PlausibilityCheck:");
                    continue; // Go to next statement
                }
                Statement::Assign { value, line: l, .. } => {
                    check_expr = Some(value);
                    line = *l;
                }
                Statement::IfStmt { condition, line: l, .. } => {
                    // Also check variables used in conditions
                    check_expr = Some(condition);
                    line = *l;
                }
                _ => {}
            }

            if let Some(expr) = check_expr {
                let mut vars = vec![];
                collect_vars(expr, &mut vars);
                for v in vars {
                    let up = v.to_ascii_uppercase();
                    if up.contains("HMI") || up.contains("DB") {
                        if !prev_was_plaus {
                            violations.push(Violation {
                                rule_no: 11,
                                rule_name: "Plausibility Checks",
                                line,
                                reason: format!("Use of '{}' not preceded by @PlausibilityCheck comment", v),
                                suggestion: "Add '(* @PlausibilityCheck: ... *)' immediately before usage.".into(),
                            });
                        }
                    }
                }
            }

            // Reset the flag unless the current statement was a comment
            if !matches!(st, Statement::Comment { .. }) {
                prev_was_plaus = false;
            }
        }
    }

    RuleResult::violations(violations)
}

fn collect_vars(e: &Expression, out: &mut Vec<String>) {
    match e {
        Expression::VariableRef(s) => out.push(s.clone()),
        Expression::BinaryOp { left, right, .. } => {
            collect_vars(left, out);
            collect_vars(right, out);
        }
        Expression::Index { base, index, .. } => {
            collect_vars(base, out);
            collect_vars(index, out);
        }
        _ => {}
    }
}