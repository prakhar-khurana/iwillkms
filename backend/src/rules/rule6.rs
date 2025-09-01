// Replaced File

//! Rule 6: Validate timers and counters.
//! Detect untrusted recipe/HMI data flowing into timer preset arguments (e.g., TP/PT),
//! but only when there is no dominating range/limit guard or nearby validation annotation.

use crate::ast::{Expression, Program, Statement, BinOp};
use super::{RuleResult, Violation, utils};
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
                let mut rhs_vars = HashSet::new();
                collect_vars(value, &mut rhs_vars);
                let rhs_is_tainted = expr_has_sensitive_source(value) || rhs_vars.iter().any(|v| tainted.contains(v));

                let is_sanitized = is_guarded_by_range(&rhs_vars, guards) || utils::has_plausibility_annotation_above(*line, 3);
                
                // Taint propagation
                if let Expression::Identifier(target_name) = target {
                    if rhs_is_tainted && !is_sanitized {
                        tainted.insert(target_name.to_ascii_uppercase());
                    } else {
                        tainted.remove(&target_name.to_ascii_uppercase());
                    }
                }

                // Sink check
                if let Expression::Identifier(target_name) = target {
                    if is_timer_preset_sink(target_name) && rhs_is_tainted && !is_sanitized {
                        out.push(Violation {
                            rule_no: 6, rule_name: "Validate timers and counters", line: *line,
                            reason: format!("Timer preset '{}' set from unvalidated source", target_name),
                            suggestion: "Add a range/plausibility check before setting timer presets.".into(),
                        });
                    }
                }
            }
            Statement::Call { name, args, line } => {
                 for (arg_name, arg_value) in args {
                    if is_timer_call(name) && arg_name.to_ascii_uppercase() == "PT" {
                         check_timer_sink(arg_value, *line, tainted, guards, out);
                    }
                 }
            }
             Statement::Expr { expr, .. } => {
                // Also scan for timer calls that are standalone expressions, e.g. `MyTimer(IN:=1, PT:=...);`
                scan_expr_for_sinks(expr, tainted, guards, out);
            }
            Statement::IfStmt { condition, then_branch, else_branch, .. } => {
                let mut then_taint = tainted.clone();
                guards.push(condition);
                walk_statements(then_branch, &mut then_taint, guards, out);
                guards.pop();

                let mut else_taint = tainted.clone();
                walk_statements(else_branch, &mut else_taint, guards, out);
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

fn scan_expr_for_sinks<'a>(expr: &'a Expression, tainted: &mut HashSet<String>, guards: &mut Vec<&'a Expression>, out: &mut Vec<Violation>) {
     if let Expression::FuncCall { name, args, line, .. } = expr {
        // For positional calls, the preset time (PT) is usually the second argument.
        if is_timer_call(name) {
            if let Some(pt_arg) = args.get(1) {
                check_timer_sink(pt_arg, *line, tainted, guards, out);
            }
        }
        // Recurse into arguments in case of nested calls.
        for arg in args {
            scan_expr_for_sinks(arg, tainted, guards, out);
        }
     }
}

fn check_timer_sink<'a>(arg_value: &'a Expression, line: usize, tainted: &HashSet<String>, guards: &mut Vec<&'a Expression>, out: &mut Vec<Violation>) {
    let mut arg_vars = HashSet::new();
    collect_vars(arg_value, &mut arg_vars);
    let arg_is_tainted = expr_has_sensitive_source(arg_value) || arg_vars.iter().any(|v| tainted.contains(v));
    let is_sanitized = is_guarded_by_range(&arg_vars, guards) || utils::has_plausibility_annotation_above(line, 3);

    if arg_is_tainted && !is_sanitized {
         out.push(Violation {
            rule_no: 6,
            rule_name: "Validate timers and counters",
            line,
            reason: format!("Timer preset comes from unvalidated source '{}'", utils::expr_text(arg_value)),
            suggestion: "Add a range/plausibility check (or @PlausibilityCheck) before setting timer PT.".into(),
        });
    }
}

fn is_timer_call(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    up.ends_with("TP") || up.ends_with("TON") || up.ends_with("TOF")
}

fn is_timer_preset_sink(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    up.contains("TIMER") && (up.contains("PRESET") || up.ends_with("_PT"))
}

// Re-usable helper functions
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

fn is_guarded_by_range(vars: &HashSet<String>, guards: &[&Expression]) -> bool {
    vars.iter().any(|var| {
        guards.iter().any(|guard| is_var_constrained(var, guard))
    })
}

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
            is_var_constrained(var_name, left) || is_var_constrained(var_name, right)
        }
        Expression::UnaryOp { expr, .. } => is_var_constrained(var_name, expr),
        _ => false,
    }
}