//! Rule 5: Use checksum integrity checks.
//! Heuristic: if sensitive data (e.g. recipe) is used, there must be
//! evidence of a checksum/CRC comparison that can raise an alarm.

use crate::ast::{Expression, Program, Statement};
use super::{RuleResult, Violation, utils::expr_text}; // Use central utility

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];

    for f in &program.functions {
        let mut sensitive_usage_line: Option<usize> = None;
        
        // First, determine if sensitive data is used anywhere in this function.
        if function_uses_sensitive_data(&f.statements) {
            sensitive_usage_line = Some(f.line); // Report at the function level for now
        }

        // If it is, then check if the same function performs an integrity check.
        if let Some(line) = sensitive_usage_line {
            if !has_integrity_check(&f.statements) {
                violations.push(Violation {
                    rule_no: 5,
                    rule_name: "Use checksum integrity checks",
                    line,
                    reason: "Function uses recipe/parameter data without a visible integrity check.".into(),
                    suggestion: "Verify a checksum/CRC for recipe data and raise an alarm on mismatch before using the data.".into(),
                });
            }
        }
    }

    RuleResult::violations(violations)
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
            _ => {}
        }
    }
    false
}

fn expr_contains_sensitive_vars(e: &Expression) -> bool {
    let mut vars = Vec::new();
    find_vars(e, &mut vars);
    vars.iter().any(|v| {
        let up = v.to_ascii_uppercase();
        up.contains("RECIPE") || up.contains("PARAMETER") || up.contains(".PAR.")
    })
}

fn has_integrity_check(stmts: &[Statement]) -> bool {
    for st in stmts {
        if let Statement::IfStmt { condition, then_branch, .. } = st {
            let c = expr_text(condition).to_ascii_uppercase();
            if (c.contains("CHECKSUM") || c.contains("CRC")) && (c.contains("<>") || c.contains("!=")) {
                // Check if the THEN branch sets an alarm
                if then_branch.iter().any(|s| {
                    if let Statement::Assign { target, .. } = s {
                        return target.name.to_ascii_uppercase().contains("ALARM");
                    }
                    false
                }) {
                    return true;
                }
            }
            if has_integrity_check(then_branch) { return true; }
        }
    }
    false
}

fn find_vars(e: &Expression, out: &mut Vec<String>) {
    match e {
        Expression::VariableRef(s) => out.push(s.clone()),
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