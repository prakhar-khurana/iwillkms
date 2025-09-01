//! Rule 8: Validate HMI input variables.
//! Taint propagation from HMI/recipe sources to sensitive sinks,
//! suppressed by nearby @PlausibilityCheck or dominating range/limit guards.

use crate::ast::{Expression, Program, Statement, BinOp};
use super::{utils, RuleResult, Violation};
use std::collections::HashSet;

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];

    for f in &program.functions {
        // Start with an empty set of tainted variables and an empty guard stack.
        walk_statements(&f.statements, &mut HashSet::new(), &mut vec![], &mut violations);
    }

    RuleResult::violations(violations)
}

fn walk_statements<'a>(
    stmts: &'a [Statement],
    tainted: &mut HashSet<String>,
    guards: &mut Vec<&'a Expression>,
    out: &mut Vec<Violation>,
) {
    for st in stmts {
        match st {
            Statement::Assign { target, value, line } => {
                if let Expression::Identifier(target_name) = target {
                    let mut rhs_vars = HashSet::new();
                    collect_vars(value, &mut rhs_vars);

                    let rhs_is_tainted = expr_has_sensitive_source(value) || rhs_vars.iter().any(|v| tainted.contains(v));

                    // A variable is sanitized if it's guarded by a range check or has a plausibility annotation.
                    let is_sanitized = is_guarded_by_range(&rhs_vars, guards) || utils::has_plausibility_annotation_above(*line, 3);

                    if rhs_is_tainted && !is_sanitized {
                        tainted.insert(target_name.to_ascii_uppercase());
                    } else {
                        // If it's sanitized, it's no longer tainted.
                        tainted.remove(&target_name.to_ascii_uppercase());
                    }

                    // Check for sink violation at the point of assignment.
                    if is_assignment_sink(target_name) && rhs_is_tainted && !is_sanitized {
                        out.push(Violation {
                            rule_no: 8,
                            rule_name: "Validate HMI input variables",
                            line: *line,
                            reason: format!("Untrusted data flows into sensitive variable '{}'", target_name),
                            suggestion: "Add plausibility/authorization checks (range limits, state checks) or a nearby @PlausibilityCheck.".into(),
                        });
                    }
                }
            }

            Statement::IfStmt { condition, then_branch, else_branch, .. } => {
                // Handle branching paths for taint analysis correctly.
                let mut then_taint = tainted.clone();
                guards.push(condition);
                walk_statements(then_branch, &mut then_taint, guards, out);
                guards.pop();

                let mut else_taint = tainted.clone();
                walk_statements(else_branch, &mut else_taint, guards, out);

                // Merge the tainted sets from both branches. A variable is tainted if it's tainted in either path.
                *tainted = then_taint.union(&else_taint).cloned().collect();
            }

            Statement::CaseStmt { cases, else_branch, .. } => {
                let mut merged_taint = tainted.clone();
                for (_, body) in cases {
                    let mut case_taint = tainted.clone();
                    walk_statements(body, &mut case_taint, guards, out);
                    merged_taint = merged_taint.union(&case_taint).cloned().collect();
                }
                
                let mut else_taint = tainted.clone();
                walk_statements(else_branch, &mut else_taint, guards, out);
                *tainted = merged_taint.union(&else_taint).cloned().collect();
            }
            _ => {}
        }
    }
}

// Helper functions (mostly unchanged, but now used with correct AST context)

fn is_assignment_sink(target_name: &str) -> bool {
    let up = target_name.to_ascii_uppercase();
    up.contains("MOTOR") || up.contains("SPEED") || up.contains("SETPOINT") || up.contains("POSITION") || up.contains("COMMAND") || up.contains("CMD")
}

fn expr_has_sensitive_source(e: &Expression) -> bool {
    let mut vars = HashSet::new();
    collect_vars(e, &mut vars);
    vars.iter().any(|v| utils::is_sensitive_variable(v))
}

fn collect_vars(e: &Expression, out: &mut HashSet<String>) {
    match e {
        Expression::Identifier(s) => { out.insert(s.to_ascii_uppercase()); }
        Expression::BinaryOp { left, right, .. } => { collect_vars(left, out); collect_vars(right, out); }
        Expression::Index { base, index, .. } => { collect_vars(base, out); collect_vars(index, out); }
        Expression::FuncCall { args, .. } => { for arg in args { collect_vars(arg, out); } }
        _ => {}
    }
}

/// Checks if any of the given variables are constrained by any of the active guards.
fn is_guarded_by_range(vars: &HashSet<String>, guards: &[&Expression]) -> bool {
    vars.iter().any(|var| {
        guards.iter().any(|guard| is_var_constrained(var, guard))
    })
}

/// Recursively checks if a guard expression `g` places a range constraint on `var_name`.
fn is_var_constrained(var_name: &str, g: &Expression) -> bool {
    match g {
        Expression::BinaryOp { op, left, right, .. } => {
            let is_comparison = matches!(op, BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge | BinOp::Eq | BinOp::Neq);
            if is_comparison {
                let left_text = utils::expr_text(left).to_ascii_uppercase();
                let right_text = utils::expr_text(right).to_ascii_uppercase();
                if (left_text == *var_name && matches!(**right, Expression::NumberLiteral(..))) ||
                   (right_text == *var_name && matches!(**left, Expression::NumberLiteral(..))) {
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