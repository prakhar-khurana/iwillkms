//! Rule 4: Use PLC flags as integrity checks around division.
//! Flag any `/` operations that are *not* inside a conditional checking
//! status word flags (e.g., SW.OV=0 AND SW.OS=0) or zero divisor.

use crate::ast::{BinOp, Expression, Program, Statement};
use super::{utils, RuleResult, Violation};

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];

    for f in &program.functions {
        collect_div_violations(&f.statements, /*guarded*/ false, &mut violations);
    }

    RuleResult::violations(violations)
}

fn collect_div_violations(stmts: &[Statement], guarded: bool, out: &mut Vec<Violation>) {
    for st in stmts {
        match st {
            Statement::IfStmt { condition, then_branch, else_branch, .. } => {
                let is_valid_guard = is_division_guard(condition);
                // The `then` branch is guarded if we are already in a guarded block OR the new condition is a valid guard.
                collect_div_violations(then_branch, guarded || is_valid_guard, out);
                // The `else` branch is only guarded if we were already in a guarded block.
                collect_div_violations(else_branch, guarded, out);
            }

            Statement::Assign { value, line, .. } | Statement::Expr { expr: value, line } => {
                find_divs(value, *line, guarded, out);
            }
            _ => {}
        }
    }
}

fn find_divs(expr: &Expression, line: usize, guarded: bool, out: &mut Vec<Violation>) {
    match expr {
        Expression::BinaryOp { op: BinOp::Div, .. } => {
            if !guarded {
                out.push(Violation {
                    rule_no: 4,
                    rule_name: "Use PLC flags as integrity checks",
                    line,
                    reason: "Division operation without status-word / zero-divisor guard".into(),
                    suggestion: "Wrap division inside IF SW.OV=0 AND SW.OS=0 AND divisor<>0 THEN ...".into(),
                });
            }
            // Don't recurse into children of a division; one violation is enough.
        }
        Expression::BinaryOp { left, right, .. } => {
            find_divs(left, line, guarded, out);
            find_divs(right, line, guarded, out);
        }
        Expression::Index { base, index, .. } => {
            find_divs(base, line, guarded, out);
            find_divs(index, line, guarded, out);
        }
        _ => {}
    }
}

/// Checks if an expression is a valid guard for a division operation.
/// This is a simplified check; a more robust implementation would parse the
/// divisor from the guarded block and ensure it's the one being checked.
fn is_division_guard(e: &Expression) -> bool {
    let text = utils::expr_text(e).replace(' ', "").to_ascii_uppercase();
    let has_sw_check = text.contains("SW.OV=0") && text.contains("SW.OS=0");
    let has_zero_check = text.contains("<>0") || text.contains("!=0");
    has_sw_check || has_zero_check
}