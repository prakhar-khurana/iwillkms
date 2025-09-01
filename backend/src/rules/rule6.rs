//! Rule 6: Validate timers and counters.
//! Detect untrusted recipe/HMI data flowing into timer preset arguments (e.g., TP/PT),
//! but only when there is no dominating range/limit guard or nearby validation annotation.

use crate::ast::{Expression, Program, Statement};
use super::{RuleResult, Violation, utils, utils::expr_text};
use std::collections::HashSet;

pub fn check(program: &Program) -> RuleResult {
    let mut violations = Vec::new();

    for f in &program.functions {
        let mut tainted = HashSet::<String>::new();
        scan(&f.statements, &mut tainted, /*enclosing_guard=*/String::new(), &mut violations);
    }

    if violations.is_empty() {
        RuleResult::ok(6, "Validate timers and counters")
    } else {
        RuleResult::violations(violations)
    }
}

fn scan(
    stmts: &[Statement],
    tainted: &mut HashSet<String>,
    guard_text: String,
    out: &mut Vec<Violation>,
) {
    for st in stmts {
        match st {
            Statement::Assign { target, value, line } => {
                if let Expression::VariableRef(target_name) = target {
                    let target_up = target_name.to_ascii_uppercase();
                    let mut rhs_vars = HashSet::new();
                    collect_vars(value, &mut rhs_vars);
                    let rhs_is_tainted = is_source(value) || rhs_vars.iter().any(|v| tainted.contains(v));

                    if rhs_is_tainted {
                        let annotated = utils::has_plausibility_annotation_above(*line, 3);
                        let guard_validates = guard_has_range_or_limit(&guard_text);
                        if annotated || guard_validates {
                            tainted.remove(&target_up);
                        } else {
                            tainted.insert(target_up);
                        }
                    } else {
                        tainted.remove(&target_up);
                    }

                    // Also check if this assignment itself is a sink
                    if is_timer_preset_sink(target_name, None) && rhs_is_tainted {
                        let annotated = utils::has_plausibility_annotation_above(*line, 3);
                        let has_range = guard_has_range_or_limit(&guard_text);
                        if !(annotated || has_range) {
                            out.push(Violation {
                                rule_no: 6, rule_name: "Validate timers and counters", line: *line,
                                reason: format!("Timer preset '{}' set from unvalidated source", target_name),
                                suggestion: "Add a range/plausibility check before setting timer presets.".into(),
                            });
                        }
                    }
                }
            }

            Statement::IfStmt { condition, then_branch, else_branch, .. } => {
                let cond_txt = expr_text(condition).to_ascii_uppercase();
                let new_guard = join_guards(&guard_text, &cond_txt);

                let mut then_taint = tainted.clone();
                scan(then_branch, &mut then_taint, new_guard, out);

                let mut else_taint = tainted.clone();
                scan(else_branch, &mut else_taint, guard_text.clone(), out);

                *tainted = then_taint.union(&else_taint).cloned().collect();
            }

            // Note: your AST's CaseStmt has no 'selector' field; labels are Vec<Expression>.
            Statement::CaseStmt { cases, else_branch, .. } => {
                let mut accum = tainted.clone();
                for (_labels, body) in cases {
                    let mut branch_taint = tainted.clone();
                    scan(body, &mut branch_taint, guard_text.clone(), out);
                    accum = accum.union(&branch_taint).cloned().collect();
                }
                let mut else_taint = tainted.clone();
                scan(else_branch, &mut else_taint, guard_text.clone(), out);
                *tainted = accum.union(&else_taint).cloned().collect();
            }

            Statement::Expr { expr, .. } => {
                // Also scan for timer calls that are standalone expressions
                scan_expr_for_sinks(expr, tainted, &guard_text, out);
            }

            Statement::Call { name, args, line, .. } => {
                for (arg_name, arg_value) in args {
                    check_timer_sink(name, Some(arg_name), arg_value, *line, tainted, &guard_text, out);
                }
            }

            _ => {}
        }
    }
}

/// Recursively scans an expression for timer calls and checks for tainted presets.
fn scan_expr_for_sinks(
    expr: &Expression,
    tainted: &HashSet<String>,
    guard_text: &str,
    out: &mut Vec<Violation>,
) {
    match expr {
        Expression::FuncCall { name, args, line, .. } => {
            // For positional calls, assume PT is the second argument.
            if let Some(pt_arg) = args.get(1) {
                check_timer_sink(name, None, pt_arg, *line, tainted, guard_text, out);
            }
            // Recurse into arguments
            for arg in args {
                scan_expr_for_sinks(arg, tainted, guard_text, out);
            }
        }
        Expression::BinaryOp { left, right, .. } => {
            scan_expr_for_sinks(left, tainted, guard_text, out);
            scan_expr_for_sinks(right, tainted, guard_text, out);
        }
        Expression::Index { base, index, .. } => {
            scan_expr_for_sinks(base, tainted, guard_text, out);
            scan_expr_for_sinks(index, tainted, guard_text, out);
        }
        _ => {}
    }
}

/// Centralized logic to check if a timer argument is a tainted sink.
fn check_timer_sink(
    call_name: &str,
    arg_name: Option<&str>,
    arg_value: &Expression,
    line: usize,
    tainted: &HashSet<String>,
    guard_text: &str,
    out: &mut Vec<Violation>,
) {
    let mut arg_vars = HashSet::new();
    collect_vars(arg_value, &mut arg_vars);
    let arg_is_tainted = is_source(arg_value) || arg_vars.iter().any(|v| tainted.contains(v));

    if is_timer_preset_sink(call_name, arg_name) && arg_is_tainted {
        let annotated = utils::has_plausibility_annotation_above(line, 3);
        let has_range = guard_has_range_or_limit(guard_text);
        if !(annotated || has_range) {
            out.push(Violation {
                rule_no: 6,
                rule_name: "Validate timers and counters",
                line,
                reason: format!("Timer preset comes from unvalidated source '{}'", expr_text(arg_value)),
                suggestion: "Add a range/plausibility check (or @PlausibilityCheck) before setting timer PT.".into(),
            });
        }
    }
}

fn is_source(e: &Expression) -> bool {
    let mut vars = HashSet::new();
    collect_vars(e, &mut vars);
    vars.iter().any(|v| utils::is_sensitive_variable(v))
}

fn is_timer_preset_sink(call_name: &str, arg_name: Option<&str>) -> bool {
    let call_up = call_name.to_ascii_uppercase();
    if let Some(arg) = arg_name {
        // It's a function call with a named argument, e.g., `TON(PT := ...)`
        let is_timer_call = call_up.ends_with("TP") || call_up.ends_with("TON") || call_up.ends_with("TOF");
        let is_pt_arg = arg.to_ascii_uppercase() == "PT";
        is_timer_call && is_pt_arg
    } else {
        // It's a variable assignment, e.g., `MyTimerPreset := ...`
        // or a positional function call.
        let is_timer_call = call_up.ends_with("TP") || call_up.ends_with("TON") || call_up.ends_with("TOF");
        let is_preset_var = call_up.contains("PRESET") || call_up.contains("_PT");
        is_timer_call || is_preset_var
    }
}

fn collect_vars(e: &Expression, out: &mut HashSet<String>) {
    match e {
        Expression::VariableRef(s) => { out.insert(s.to_ascii_uppercase()); },
        Expression::BinaryOp { left, right, .. } => { collect_vars(left, out); collect_vars(right, out); }
        Expression::Index { base, index, .. } => { collect_vars(base, out); collect_vars(index, out); }
        Expression::FuncCall { args, .. } => { for arg in args { collect_vars(arg, out); } }
        _ => {}
    }
}

fn join_guards(parent: &str, child: &str) -> String {
    if parent.is_empty() { child.to_string() }
    else if child.is_empty() { parent.to_string() }
    else { format!("({}) AND ({})", parent, child) }
}

fn guard_has_range_or_limit(guard: &str) -> bool {
    if guard.is_empty() { return false; }
    let g = guard.replace(' ', "").to_ascii_uppercase();
    let has_cmp = g.contains("<=") || g.contains(">=") || g.contains('<') || g.contains('>');
    let has_keywords = g.contains("LIMIT") || g.contains("BOUND") || g.contains("MIN") || g.contains("MAX") || g.contains("RANGE");
    let nonzero = g.contains("!=0") || g.contains("<>0");
    has_cmp || has_keywords || nonzero
}
