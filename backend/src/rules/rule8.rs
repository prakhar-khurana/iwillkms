//! Rule 8: Validate HMI input variables.
//! Taint propagation from HMI/recipe sources to sensitive sinks,
//! suppressed by nearby @PlausibilityCheck or dominating range/limit guards.

use crate::ast::{BinOp, Expression, Program, Statement};
use super::{utils, utils::expr_text, RuleResult, Violation};
use std::collections::HashSet;

pub fn check(program: &Program) -> RuleResult {
    let mut violations = Vec::new();

    for f in &program.functions {
        let mut tainted = HashSet::<String>::new();
        scan(&f.statements, &mut tainted, /*guard stack*/Vec::new(), &mut violations);
    }

    if violations.is_empty() {
        RuleResult::ok(8, "Validate HMI input variables")
    } else {
        for v in violations.iter_mut() { v.rule_no = 8; v.rule_name = "Validate HMI input variables".into(); }
        RuleResult::violations(violations)
    }
}

fn scan(stmts: &[Statement], tainted: &mut HashSet<String>, guard_stack: Vec<String>, out: &mut Vec<Violation>) {
    for st in stmts {
        match st {
            Statement::Assign { target, value, line } => {
                if let Expression::VariableRef(target_name) = target {
                    let mut rhs_vars = HashSet::new();
                    collect_vars(value, &mut rhs_vars);

                    let rhs_is_tainted = expr_has_sensitive_source(value) || rhs_vars.iter().any(|v| tainted.contains(v));

                    let annotated = utils::has_plausibility_annotation_above(*line, 3);
                    let guard_text = current_guard_for_line(*line, &guard_stack);
                    let guard_validates = guard_has_validation_for(&guard_text, &rhs_vars);

                    if rhs_is_tainted && !(annotated || guard_validates) {
                        tainted.insert(target_name.to_ascii_uppercase());
                    } else {
                        tainted.remove(&target_name.to_ascii_uppercase());
                    }

                    if is_assignment_sink(target_name) && rhs_is_tainted && !(annotated || guard_validates) {
                        out.push(Violation {
                            rule_no: 8,
                            rule_name: "Validate HMI input variables".into(),
                            line: *line,
                            reason: format!("Untrusted data flows into sensitive variable '{}'", target_name),
                            suggestion: "Add plausibility/authorization checks (range limits, state checks) or a nearby @PlausibilityCheck.".into(),
                        });
                    }
                }
            }

            Statement::IfStmt { condition, then_branch, else_branch, .. } => {
                let cond_txt = expr_text(condition).to_ascii_uppercase();

                let mut then_taint = tainted.clone();
                let mut then_stack = guard_stack.clone();
                then_stack.push(cond_txt);
                scan(then_branch, &mut then_taint, then_stack, out);

                let mut else_taint = tainted.clone();
                scan(else_branch, &mut else_taint, guard_stack.clone(), out);

                *tainted = then_taint.union(&else_taint).cloned().collect();
            }

            // CaseStmt: labels are Vec<Expression>; we don't need them for taint here.
            Statement::CaseStmt { cases, else_branch, .. } => {
                let mut merged = tainted.clone();
                for (_labels, body) in cases {
                    let mut branch_taint = tainted.clone();
                    scan(body, &mut branch_taint, guard_stack.clone(), out);
                    merged = merged.union(&branch_taint).cloned().collect();
                }
                let mut else_taint = tainted.clone();
                scan(else_branch, &mut else_taint, guard_stack.clone(), out);
                *tainted = merged.union(&else_taint).cloned().collect();
            }

            Statement::Call { .. } => {}

            _ => {}
        }
    }
}

fn is_assignment_sink(target_name: &str) -> bool {
    let up = target_name.to_ascii_uppercase();
    up.contains("MOTOR")
        || up.contains("SPEED")
        || up.contains("SETPOINT")
        || up.contains("POSITION")
        || up.contains("COMMAND")
        || up.contains("CMD")
}

fn expr_has_sensitive_source(e: &Expression) -> bool {
    let mut vars = HashSet::new();
    collect_vars(e, &mut vars);
    vars.iter().any(|v| utils::is_sensitive_variable(v))
}

fn collect_vars(e: &Expression, out: &mut HashSet<String>) {
    match e {
        Expression::VariableRef(s) => { out.insert(s.to_ascii_uppercase()); }
        Expression::BinaryOp { left, right, .. } => { collect_vars(left, out); collect_vars(right, out); }
        Expression::Index { base, index, .. } => { collect_vars(base, out); collect_vars(index, out); }
        Expression::FuncCall { args, .. } => { for arg in args { collect_vars(arg, out); } }
        _ => {}
    }
}

fn current_guard_for_line(line: usize, guard_stack: &[String]) -> String {
    let precise = utils::current_guard_text(line);
    if !precise.is_empty() { return precise.to_ascii_uppercase(); }
    guard_stack.iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>().join(" AND ").to_ascii_uppercase()
}

fn guard_has_validation_for(guard_text: &str, rhs_vars: &HashSet<String>) -> bool {
    if guard_text.is_empty() { return false; }
    let g = guard_text.replace(' ', "").to_ascii_uppercase();
    rhs_vars.iter().any(|v| {
        let v = v.replace(' ', "");
        (g.contains(&v) && (g.contains("<=") || g.contains(">=") || g.contains('<') || g.contains('>')))
            || g.contains("LIMIT") || g.contains("BOUND") || g.contains("RANGE")
            || g.contains("MIN") || g.contains("MAX")
            || (g.contains(&v) && (g.contains("!=0") || g.contains("<>0")))
    })
}
