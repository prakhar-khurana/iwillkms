//! Rule 15: Define a safe restart state.
//! Verify non-empty OB100 exists and critical outputs are initialized to a safe value (FALSE/0).

use crate::ast::{Expression, FunctionKind, Program, Statement};
use super::{RuleResult, Violation};

pub fn check(program: &Program) -> RuleResult {
    let mut violations = Vec::new();

    let ob100 = program.functions.iter().find(|f| f.kind == FunctionKind::OB100);

    match ob100 {
        None => {
            violations.push(Violation {
                rule_no: 15,
                rule_name: "Define a safe restart state",
                line: 0,
                reason: "OB100 (Startup OB) not found".into(),
                suggestion: "Add OB100 and initialize critical outputs to a safe state.".into(),
            });
            return RuleResult::violations(violations);
        }
        Some(f) if f.statements.is_empty() => {
            violations.push(Violation {
                rule_no: 15,
                rule_name: "Define a safe restart state",
                line: f.line,
                reason: "OB100 exists but is empty".into(),
                suggestion: "Initialize critical outputs to FALSE/0 in OB100.".into(),
            });
            return RuleResult::violations(violations);
        }
        Some(f) => {
            let mut safe_inits: Vec<(usize, String)> = Vec::new();
            let mut unsafe_inits: Vec<(usize, String)> = Vec::new();
            walk_ob100(&f.statements, &mut safe_inits, &mut unsafe_inits);

            for (line, var) in unsafe_inits {
                violations.push(Violation {
                    rule_no: 15,
                    rule_name: "Define a safe restart state",
                    line,
                    reason: format!("Critical output '{}' initialized UNSAFELY on restart", var),
                    suggestion: "Initialize critical outputs to FALSE/0 in OB100.".into(),
                });
            }

            if safe_inits.is_empty() {
                violations.push(Violation {
                    rule_no: 15,
                    rule_name: "Define a safe restart state",
                    line: f.line,
                    reason: "OB100 does not initialize any critical output to a safe value".into(),
                    suggestion: "Set critical outputs to FALSE/0 in OB100.".into(),
                });
            }

            return RuleResult::violations(violations);
        }
    }
}

fn walk_ob100(
    stmts: &[Statement],
    safe_inits: &mut Vec<(usize, String)>,
    unsafe_inits: &mut Vec<(usize, String)>,
) {
    for st in stmts {
        match st {
            Statement::Assign { target, value, line } => {
                let name = &target.name;
                if looks_like_critical_output(name) {
                    if is_safe_expr(value) {
                        safe_inits.push((*line, name.clone()));
                    } else if is_unsafe_expr(value) {
                        unsafe_inits.push((*line, name.clone()));
                    }
                }
            }
            Statement::IfStmt { then_branch, else_branch, .. } => {
                walk_ob100(then_branch, safe_inits, unsafe_inits);
                walk_ob100(else_branch, safe_inits, unsafe_inits);
            }
            Statement::CaseStmt { cases, else_branch, .. } => {
                for (_, body) in cases {
                    walk_ob100(body, safe_inits, unsafe_inits);
                }
                walk_ob100(else_branch, safe_inits, unsafe_inits);
            }
            _ => {}
        }
    }
}

fn looks_like_critical_output(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    up.contains("CRITICAL") || up.contains("SAFE") || up.ends_with("_OUT") || up.contains("MOTOR") || up.contains("OUTPUT")
}

fn is_safe_expr(e: &Expression) -> bool {
    match e {
        Expression::BoolLiteral(false, _) => true,
        Expression::NumberLiteral(n, _) => *n == 0,
        _ => false,
    }
}

fn is_unsafe_expr(e: &Expression) -> bool {
    match e {
        Expression::BoolLiteral(true, _) => true,
        Expression::NumberLiteral(n, _) => *n != 0,
        _ => false,
    }
}
