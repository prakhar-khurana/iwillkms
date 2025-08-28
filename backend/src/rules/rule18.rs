//! Rule 18: Log PLC hard stops.
//! Verify OB86 (Rack Failure), OB121 (Programming Error), OB82 (Diagnostic Interrupt)
//! exist and contain at least one diagnostic/alarm action.

use crate::ast::{FunctionKind, Program, Statement};
use super::{RuleResult, Violation};

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];
    check_ob(program, FunctionKind::OB86, "OB86 (Rack Failure)", &mut violations);
    check_ob(program, FunctionKind::OB121, "OB121 (Programming Error)", &mut violations);
    check_ob(program, FunctionKind::OB82, "OB82 (Diagnostic Interrupt)", &mut violations);

    RuleResult::violations(violations)
}

fn check_ob(program: &Program, kind: FunctionKind, name: &str, out: &mut Vec<Violation>) {
    if let Some(f) = program.functions.iter().find(|fb| fb.kind == kind) {
        if f.statements.is_empty() {
            out.push(Violation {
                rule_no: 18,
                rule_name: "Log PLC hard stops",
                line: f.line,
                reason: format!("{name} present but empty"),
                suggestion: "Log/record diagnostics and take safe action in this OB.".into(),
            });
            return;
        }
        if !has_diag_action(&f.statements) {
            out.push(Violation {
                rule_no: 18,
                rule_name: "Log PLC hard stops",
                line: f.line,
                reason: format!("{name} present but no diagnostic/alarm action"),
                suggestion: "Write a diagnostic/alarm/record action in this OB.".into(),
            });
        }
    } else {
        out.push(Violation {
            rule_no: 18,
            rule_name: "Log PLC hard stops",
            line: 0,
            reason: format!("{name} missing or empty"),
            suggestion: format!("Implement {name} to capture and log diagnostics.").into(),
        });
    }
}

fn has_diag_action(stmts: &[Statement]) -> bool {
    for st in stmts {
        match st {
            Statement::Assign { target, value, .. } => {
                let t = target.name.to_ascii_uppercase();
                let v = super::utils::expr_text(value).to_ascii_uppercase();
                if t.contains("ALARM") || t.contains("DIAG") || t.contains("FAULT") || v.contains("LOG") {
                    return true;
                }
            }
            Statement::Call { name, .. } => {
                let n = name.to_ascii_uppercase();
                if n.contains("ALARM") || n.contains("DIAG") || n.contains("LOG") {
                    return true;
                }
            }
            Statement::IfStmt { then_branch, else_branch, .. } => {
                if has_diag_action(then_branch) || has_diag_action(else_branch) { return true; }
            }
            Statement::CaseStmt { cases, else_branch, .. } => {
                for (_, body) in cases {
                    if has_diag_action(body) { return true; }
                }
                if has_diag_action(else_branch) { return true; }
            }
            _ => {}
        }
    }
    false
}
