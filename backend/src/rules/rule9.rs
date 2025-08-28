//! Rule 9: Validate indirections (array indexing and unsafe calls).
//! Flag any MyArray[IndexVar] that is not guarded by range checks.
//! Also flag calls to known unsafe functions like strcpy.

use crate::ast::{Expression, Program, Statement}; // Removed BinOp, UnaryOp
use super::{RuleResult, Violation, utils::expr_text}; // Import the central utility

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];

    for f in &program.functions {
        walk_for_indexing(&f.statements, &mut vec![], &mut violations);
        walk_for_unsafe_calls(&f.statements, &mut violations);
    }

    RuleResult::violations(violations)
}

// --- Check 1: Array Indexing ---
fn walk_for_indexing(stmts: &[Statement], guards: &mut Vec<String>, out: &mut Vec<Violation>) {
    for st in stmts {
        match st {
            Statement::IfStmt { condition, then_branch, else_branch, .. } => {
                guards.push(expr_text(condition));
                walk_for_indexing(then_branch, guards, out);
                walk_for_indexing(else_branch, guards, out);
                guards.pop();
            }
            Statement::Assign { value, line, .. } | Statement::Expr { expr: value, line } => {
                find_index_violations(value, *line, guards, out);
            }
            _ => {}
        }
    }
}

fn find_index_violations(e: &Expression, line: usize, guards: &Vec<String>, out: &mut Vec<Violation>) {
    match e {
        Expression::Index { base, index, .. } => {
            let idx_txt = expr_text(index);
            let idx_up = idx_txt.to_ascii_uppercase();
            let guarded = guards.iter().any(|g| {
                let g = g.replace(' ', "").to_ascii_uppercase();
                let idx = idx_up.replace(' ', "");
                (g.contains(&idx) && (g.contains("<") || g.contains("<=") || g.contains("BOUND") || g.contains("LIMIT")))|| g.contains(&format!("NOT({}>", idx)) // simple negated form
            });
            if !guarded && matches!(**index, Expression::VariableRef(_)) {
                out.push(Violation {
                    rule_no: 9,
                    rule_name: "Validate indirections",
                    line,
                    reason: format!("Array indexed by variable '{}' without bounds check", idx_txt),
                    suggestion: "Validate index against array bounds before access (e.g., IF index < LIMIT THEN...).".into(),
                });
            }
            find_index_violations(base, line, guards, out);
            find_index_violations(index, line, guards, out);
        }
        Expression::BinaryOp { left, right, .. } => {
            find_index_violations(left, line, guards, out);
            find_index_violations(right, line, guards, out);
        }
        Expression::FuncCall { args, .. } => {
            for arg in args {
                find_index_violations(arg, line, guards, out);
            }
        }
        _ => {}
    }
}

// --- Check 2: Unsafe Function Calls ---
fn walk_for_unsafe_calls(stmts: &[Statement], out: &mut Vec<Violation>) {
    const UNSAFE_FUNCTIONS: &[&str] = &["STRCPY", "MEMCPY", "S_MOVE"]; // Case-insensitive check
    for st in stmts {
        match st {
            Statement::Call { name, line, .. } => {
                let name_up = name.to_ascii_uppercase();
                if UNSAFE_FUNCTIONS.iter().any(|&f| name_up.contains(f)) {
                    out.push(Violation {
                        rule_no: 9,
                        rule_name: "Validate indirections",
                        line: *line,
                        reason: format!("Call to potentially unsafe function '{}'", name),
                        suggestion: "Ensure destination buffer size is checked before calling memory copy functions.".into(),
                    });
                }
            }
            Statement::IfStmt { then_branch, else_branch, .. } => {
                walk_for_unsafe_calls(then_branch, out);
                walk_for_unsafe_calls(else_branch, out);
            }
            _ => {}
        }
    }
}

// The local expr_text function has been removed.