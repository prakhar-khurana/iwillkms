//! Rule 9: Validate indirections (array indexing and unsafe calls).
//! Flag any MyArray[IndexVar] that is not guarded by range checks.
//! Also flag calls to known unsafe functions like strcpy.

use crate::ast::{BinOp, Expression, Program, Statement};
use super::{RuleResult, Violation, utils::expr_text};

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];

    for f in &program.functions {
        walk_statements(&f.statements, &mut vec![], &mut violations);
    }

    RuleResult::violations(violations)
}

fn walk_statements<'a>(stmts: &'a [Statement], guards: &mut Vec<&'a Expression>, out: &mut Vec<Violation>) {
    const UNSAFE_FUNCTIONS: &[&str] = &["STRCPY", "MEMCPY", "S_MOVE"];

    for st in stmts {
        match st {
            Statement::IfStmt { condition, then_branch, else_branch, .. } => {
                // The condition guards the `then` branch.
                guards.push(condition);
                walk_statements(then_branch, guards, out);
                guards.pop();

                // The `else` branch is walked with the original guards, but not the new one.
                walk_statements(else_branch, guards, out);
            }
            Statement::Assign { target, value, line, .. } => {
                find_violations_in_expr(target, *line, guards, out);
                find_violations_in_expr(value, *line, guards, out);
            }
            Statement::Expr { expr, line, .. } => {
                find_violations_in_expr(expr, *line, guards, out);
            }
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
            _ => {}
        }
    }
}

fn find_violations_in_expr(e: &Expression, line: usize, guards: &[&Expression], out: &mut Vec<Violation>) {
    match e {
        Expression::Index { base, index, .. } => {
            if let Expression::Identifier(idx_name) = &**index {
                let is_guarded = guards.iter().any(|g| is_var_constrained(idx_name, g));
                if !is_guarded {
                    out.push(Violation {
                        rule_no: 9,
                        rule_name: "Validate indirections",
                        line,
                        reason: format!("Array indexed by variable '{}' without bounds check", idx_name),
                        suggestion: "Validate index against array bounds before access (e.g., IF index < LIMIT THEN...).".into(),
                    });
                }
            }
            // Recurse
            find_violations_in_expr(base, line, guards, out);
            find_violations_in_expr(index, line, guards, out);
        }
        Expression::BinaryOp { left, right, .. } => {
            find_violations_in_expr(left, line, guards, out);
            find_violations_in_expr(right, line, guards, out);
        }
        Expression::FuncCall { args, .. } => {
            for arg in args {
                find_violations_in_expr(arg, line, guards, out);
            }
        }
        _ => {}
    }
}

/// Checks if a guard expression `g` places a constraint on a variable `var_name`.
fn is_var_constrained(var_name: &str, g: &Expression) -> bool {
    match g {
        Expression::BinaryOp { op, left, right, .. } => {
            // Look for `var_name <op> literal` or `literal <op> var_name`
            let is_comparison = matches!(op, BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge | BinOp::Eq | BinOp::Neq);
            if is_comparison {
                let left_text = expr_text(left).trim().to_string();
                let right_text = expr_text(right).trim().to_string();
                if (left_text.eq_ignore_ascii_case(var_name.trim()) && matches!(**right, Expression::NumberLiteral(..))) ||
                   (right_text.eq_ignore_ascii_case(var_name.trim()) && matches!(**left, Expression::NumberLiteral(..))) {
                    return true;
                }
            }
            // Recurse for compound conditions like `X > 0 AND X < 10`
            is_var_constrained(var_name, left) || is_var_constrained(var_name, right)
        }
        Expression::UnaryOp { expr, .. } => is_var_constrained(var_name, expr),
        _ => false,
    }
}