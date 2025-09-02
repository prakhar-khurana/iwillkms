//! Rule 5: Use checksum integrity checks.
//! Heuristic: if sensitive data (e.g. recipe) is used, there must be
//! evidence of a checksum/CRC comparison that can raise an alarm.

use crate::ast::{Expression, Program, Statement};
use super::{RuleResult, Violation, utils}; // Use central utility

pub fn check(program: &Program) -> RuleResult {
    for f in &program.functions {
        if function_uses_sensitive_data(&f.statements) && !has_integrity_check(&f.statements) {
            return RuleResult::violations(vec![Violation {
                rule_no: 5,
                rule_name: "Use checksum integrity checks",
                line: f.line,
                reason: format!("Function '{}' uses recipe/parameter data without a visible integrity check.", f.name),
                suggestion: "Verify a checksum/CRC for recipe data and raise an alarm on mismatch before using the data.".into(),
            }]);
        }
    }
    RuleResult::ok(5, "Use checksum integrity checks")
}


fn function_uses_sensitive_data(stmts: &[Statement]) -> bool {
    for st in stmts {
        match st {
            Statement::Assign { value, .. } => {
                if expr_contains_sensitive_vars(value) { return true; }
            }
            Statement::Call { args, .. } => {
                if args.iter().any(|(_, val)| expr_contains_sensitive_vars(val)) { return true; }
            }
            Statement::IfStmt { condition, then_branch, else_branch, .. } => {
                if expr_contains_sensitive_vars(condition) { return true; }
                if function_uses_sensitive_data(then_branch) { return true; }
                if function_uses_sensitive_data(else_branch) { return true; }
            }
            Statement::CaseStmt { cases, else_branch, .. } => {
                for (_, case_stmts) in cases {
                    if function_uses_sensitive_data(case_stmts) { return true; }
                }
                if function_uses_sensitive_data(else_branch) { return true; }
            }
            _ => {}
        }
    }
    false
}

fn expr_contains_sensitive_vars(e: &Expression) -> bool {
    let mut vars = Vec::new();
    find_vars(e, &mut vars);
    vars.iter().any(|v| utils::is_sensitive_variable(v))
}

fn has_integrity_check(stmts: &[Statement]) -> bool {
    for st in stmts {
        if let Statement::IfStmt { condition, then_branch, .. } = st {
            let c = utils::expr_text(condition).to_ascii_uppercase();
            let mentions_sens = c.contains("CHECKSUM") || c.contains("CRC");
            let is_compare = c.contains("<>") || c.contains("!=");
            let sets_alarm = then_branch.iter().any(|s| {
                if let Statement::Assign { target, .. } = s {
                    if let Expression::Identifier(name) = target {
                        return name.to_ascii_uppercase().contains("ALARM");
                    }
                }
                false
            });
            if mentions_sens && is_compare && sets_alarm { return true; }
            if has_integrity_check(then_branch) { return true; }
        }
        if let Statement::CaseStmt { cases, else_branch, .. } = st {
            for (_, case_stmts) in cases {
                if has_integrity_check(case_stmts) { return true; }
            }
            if has_integrity_check(else_branch) { return true; }
        }
    }
    false
}

fn find_vars(e: &Expression, out: &mut Vec<String>) {
    match e {
        Expression::Identifier(s) => out.push(s.clone()),
        Expression::BinaryOp { left, right, .. } => {
            find_vars(left, out);
            find_vars(right, out);
        }
        Expression::Index { base, index, .. } => {
            find_vars(base, out);
            find_vars(index, out);
        }
        Expression::FuncCall { args, .. } => {
            for arg in args {
                find_vars(arg, out);
            }
        }
        _ => {}
    }
}