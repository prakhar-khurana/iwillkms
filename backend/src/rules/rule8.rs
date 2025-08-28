//! Rules 8 & 6: Combined HMI/Timer validation using Taint Analysis.
//! Tracks variables from untrusted sources to sensitive sinks, ensuring
//! they are sanitized by checks along the way.

use crate::ast::{Expression, Program, Statement, BinOp};
use super::{RuleResult, Violation, utils::expr_text};
use std::collections::HashSet;

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];
    for f in &program.functions {
        let mut tainted_vars = HashSet::new();
        find_taint_violations(&f.statements, &mut tainted_vars, &mut violations);
    }
    RuleResult::violations(violations)
}

fn find_taint_violations(
    stmts: &[Statement],
    tainted_vars: &mut HashSet<String>,
    violations: &mut Vec<Violation>,
) {
    for st in stmts {
        match st {
            Statement::Assign { target, value, line } => {
                let mut value_vars = HashSet::new();
                collect_vars(value, &mut value_vars);

                let is_tainted = is_source(value) || value_vars.iter().any(|v| tainted_vars.contains(v));

                if is_tainted {
                    tainted_vars.insert(target.name.to_ascii_uppercase());
                } else {
                    tainted_vars.remove(&target.name.to_ascii_uppercase());
                }

                if is_assignment_a_sink(&target.name) && is_tainted {
                    violations.push(Violation {
                        rule_no: 8,
                        rule_name: "Validate HMI input variables",
                        line: *line,
                        reason: format!("Untrusted data flows into sensitive variable '{}'", target.name),
                        suggestion: "Sanitize the source variable with a range-checking IF statement before this assignment.".into(),
                    });
                }
            }
            Statement::IfStmt { condition, then_branch, else_branch, .. } => {
                let mut sanitized_vars = HashSet::new();
                let condition_vars = collect_vars_from_expr(condition);

                for var in &condition_vars {
                    if tainted_vars.contains(var) && is_sanitizer_for(condition, var) {
                        sanitized_vars.insert(var.clone());
                    }
                }

                let mut then_tainted = tainted_vars.clone();
                for var in &sanitized_vars {
                    then_tainted.remove(var);
                }
                find_taint_violations(then_branch, &mut then_tainted, violations);
                find_taint_violations(else_branch, tainted_vars, violations);
            }
            Statement::Call { name, args, line, .. } => {
                for (arg_name, arg_value) in args {
                    let mut value_vars = HashSet::new();
                    collect_vars(arg_value, &mut value_vars);

                    let is_tainted = is_source(arg_value) || value_vars.iter().any(|v| tainted_vars.contains(v));

                    if is_call_arg_a_sink(name, arg_name) && is_tainted {
                        violations.push(Violation {
                            rule_no: 6, // Report as Rule 6 for timer issues
                            rule_name: "Validate timers and counters",
                            line: *line,
                            reason: format!("Untrusted recipe data from '{}' flows into sensitive timer parameter '{}'", expr_text(arg_value), arg_name),
                            suggestion: "Validate recipe parameters against safe operational limits before use.".into(),
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

/// A "source" is where untrusted data enters the program. More specific now.
fn is_source(e: &Expression) -> bool {
    let mut vars = HashSet::new();
    collect_vars(e, &mut vars);
    vars.iter().any(|v: &String| {
        let up = v.to_ascii_uppercase();
        up.contains("HMI") || up.contains("RECIPE") || up.contains(".PAR.")
    })
}

/// Checks if an assignment target is a sensitive sink.
fn is_assignment_a_sink(target_name: &str) -> bool {
    let up = target_name.to_ascii_uppercase();
    up.contains("MOTOR") || up.contains("SPEED") || up.contains("POSITION")
}

/// Checks if a function call argument is a sensitive sink. Now context-aware.
fn is_call_arg_a_sink(call_name: &str, arg_name: &str) -> bool {
    let call_up = call_name.to_ascii_uppercase();
    let arg_up = arg_name.to_ascii_uppercase();

    // A timer preset ('PT') is a sink, especially in timer blocks (TP, TON, etc.)
    (call_up.ends_with("TP") || call_up.ends_with("TON")) && arg_up == "PT"
}

/// A "sanitizer" is a check that makes data safe by comparing it against a literal.
fn is_sanitizer_for(condition: &Expression, var_name_upper: &str) -> bool {
    match condition {
        Expression::BinaryOp { op, left, right, .. } => {
            let left_is_var = matches!(**left, Expression::VariableRef(ref v) if v.to_ascii_uppercase() == var_name_upper);
            let right_is_var = matches!(**right, Expression::VariableRef(ref v) if v.to_ascii_uppercase() == var_name_upper);
            let left_is_lit = matches!(**left, Expression::NumberLiteral(..));
            let right_is_lit = matches!(**right, Expression::NumberLiteral(..));

            match op {
                BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge | BinOp::Eq | BinOp::Neq => {
                    (left_is_var && right_is_lit) || (right_is_var && left_is_lit)
                }
                BinOp::And | BinOp::Or => {
                    is_sanitizer_for(left, var_name_upper) || is_sanitizer_for(right, var_name_upper)
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn collect_vars(e: &Expression, out: &mut HashSet<String>) {
    match e {
        Expression::VariableRef(s) => { out.insert(s.to_ascii_uppercase()); },
        Expression::BinaryOp { left, right, .. } => {
            collect_vars(left, out);
            collect_vars(right, out);
        }
        Expression::Index { base, index, .. } => {
            collect_vars(base, out);
            collect_vars(index, out);
        }
        Expression::FuncCall { args, .. } => {
            for arg in args {
                collect_vars(arg, out);
            }
        }
        _ => {}
    }
}

fn collect_vars_from_expr(e: &Expression) -> HashSet<String> {
    let mut vars = HashSet::new();
    collect_vars(e, &mut vars);
    vars
}