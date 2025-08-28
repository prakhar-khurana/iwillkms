//! Rule 4: Use PLC flags as integrity checks around division.
//! Flag any `/` operations that are *not* inside a conditional checking
//! status word flags (e.g., SW.OV=0 AND SW.OS=0) or zero divisor.

use crate::ast::{Expression, Program, Statement, BinOp};
use super::{RuleResult, Violation, utils::expr_text}; // Use the central utility

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
                let cond = expr_text(condition).to_ascii_uppercase();
                let sw_guard = cond.contains("SW.") && cond.contains("OV=0") && cond.contains("OS=0");
                let zero_guard = cond.contains("<>0") || cond.contains("!=0");
                let guarded_then = sw_guard && zero_guard;
                collect_div_violations(then_branch, guarded || guarded_then, out);
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
        Expression::BinaryOp { op: BinOp::Div, left, right, .. } => {
            if !guarded {
                out.push(Violation {
                    rule_no: 4,
                    rule_name: "Use PLC flags as integrity checks",
                    line,
                    reason: "Division operation without status-word / zero-divisor guard".into(),
                    suggestion: "Wrap division inside IF SW.OV=0 AND SW.OS=0 AND divisor<>0 THEN ...".into(),
                });
            }
            find_divs(left, line, guarded, out);
            find_divs(right, line, guarded, out);
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