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
                let mut rhs_vars = HashSet::new();
                collect_vars(value, &mut rhs_vars);
                let rhs_is_tainted = is_source(value) || rhs_vars.iter().any(|v| tainted.contains(v));

                if rhs_is_tainted {
                    let annotated = utils::has_plausibility_annotation_above(*line, 3);
                    let guard_validates = guard_has_range_or_limit(&guard_text);
                    if annotated || guard_validates {
                        tainted.remove(&target.name.to_ascii_uppercase());
                    } else {
                        tainted.insert(target.name.to_ascii_uppercase());
                    }
                } else {
                    tainted.remove(&target.name.to_ascii_uppercase());
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

            Statement::Call { name, args, line, .. } => {
                for (arg_name, arg_value) in args {
                    let mut arg_vars = HashSet::new();
                    collect_vars(arg_value, &mut arg_vars);
                    let arg_is_tainted = is_source(arg_value) || arg_vars.iter().any(|v| tainted.contains(v));

                    if is_timer_preset_sink(name, arg_name) && arg_is_tainted {
                        let annotated = utils::has_plausibility_annotation_above(*line, 3);
                        let local_guard = utils::current_guard_text(*line);
                        let has_range = guard_has_range_or_limit(&local_guard);
                        if !(annotated || has_range) {
                            out.push(Violation {
                                rule_no: 6,
                                rule_name: "Validate timers and counters",
                                line: *line,
                                reason: format!(
                                    "Timer preset comes from unvalidated source '{}'",
                                    expr_text(arg_value)
                                ),
                                suggestion: "Add a range/plausibility check (or @PlausibilityCheck) before setting timer PT.".into(),
                            });
                        }
                    }
                }
            }

            _ => {}
        }
    }
}

fn is_source(e: &Expression) -> bool {
    let mut vars = HashSet::new();
    collect_vars(e, &mut vars);
    vars.iter().any(|v| utils::is_sensitive_variable(v))
}

fn is_timer_preset_sink(call_name: &str, arg_name: &str) -> bool {
    let call_up = call_name.to_ascii_uppercase();
    let arg_up = arg_name.to_ascii_uppercase();
    (call_up.ends_with("TP") || call_up.ends_with("TON") || call_up.ends_with("TOF")) && arg_up == "PT"
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
