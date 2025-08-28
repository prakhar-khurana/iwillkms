//! Rule 15: Define a safe restart state.
//! Verify non-empty OB100 exists and critical outputs initialized to FALSE.

use crate::ast::{FunctionKind, Program, Statement};
use super::{RuleResult, Violation};

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];

    // Find OB100. Do not mutate the iterator or returned reference.
    let ob100 = program.functions.iter().find(|f| f.kind == FunctionKind::OB100);

    if let Some(f) = ob100 {
        // If OB100 exists but has no statements, that's a violation.
        if f.statements.is_empty() {
            violations.push(Violation {
                rule_no: 15,
                rule_name: "Define a safe restart state",
                line: f.line,
                reason: "OB100 exists but is empty".into(),
                suggestion: "Initialize critical outputs to FALSE in OB100.".into(),
            });
        } else {
            // Look for assignments setting critical outputs to a safe value (FALSE or 0).
            let mut has_safe_init = false;
            for st in &f.statements {
                if let Statement::Assign { target, value, .. } = st {
                    let up = target.name.to_ascii_uppercase();
                    // Heuristic: variable names containing CRITICAL or SAFE or ending with _OUT
                    if up.contains("CRITICAL") || up.contains("SAFE") || up.ends_with("_OUT") {
                        if is_false_expr(value) {
                            has_safe_init = true;
                            break;
                        }
                    }
                }
            }
            if !has_safe_init {
                violations.push(Violation {
                    rule_no: 15,
                    rule_name: "Define a safe restart state",
                    line: f.line,
                    reason: "OB100 does not initialize critical outputs to a safe value".into(),
                    suggestion: "Set critical outputs to FALSE/0 in OB100.".into(),
                });
            }
        }
    } else {
        // OB100 is missing entirely
        violations.push(Violation {
            rule_no: 15,
            rule_name: "Define a safe restart state",
            line: 0,
            reason: "OB100 (Startup OB) not found".into(),
            suggestion: "Add OB100 and initialize outputs to safe state.".into(),
        });
    }

    RuleResult::violations(violations)
}

fn is_false_expr(e: &crate::ast::Expression) -> bool {
    match e {
        crate::ast::Expression::BoolLiteral(false, _) => true,
        crate::ast::Expression::NumberLiteral(n, _) => *n == 0,
        _ => false,
    }
}
