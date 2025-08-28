use crate::{rules::RuleResult, rules::Violation};
use crate::ast::{Expression, Program, Statement};
use super::utils;
use std::collections::HashSet;

pub fn check_rule11(program: &Program) -> RuleResult {
    check_impl(program, Mode::Presence)
}

pub fn check_rule12(program: &Program) -> RuleResult {
    check_impl(program, Mode::Enforcement)
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum Mode { Presence, Enforcement }

fn check_impl(program: &Program, mode: Mode) -> RuleResult {
    let mut out = Vec::new();
    for f in &program.functions {
        walk(&f.statements, &mut out, mode);
    }
    if out.is_empty() {
        match mode {
            Mode::Presence    => RuleResult::ok(11, "Plausibility Checks"),
            Mode::Enforcement => RuleResult::ok(12, "Plausibility Checks"),
        }
    } else {
        RuleResult::violations(out)
    }
}

fn walk(stmts: &[Statement], out: &mut Vec<Violation>, mode: Mode) {
    for st in stmts {
        match st {
            Statement::Assign { target, value, line } => {
                if let Expression::VariableRef(target_name) = target {
                    let sensitive_use = expr_has_sensitive_source(value);
                    let is_sink       = is_sensitive_sink(target_name);
                    if sensitive_use && is_sink {
                        let has_nearby_annotation = utils::has_plausibility_annotation_above(*line, 3);
                        let guards_text           = utils::current_guard_text(*line);
                        let has_guard_validation  = guard_validates_value(&guards_text, value);

                        match mode {
                            Mode::Presence => {
                                if !(has_nearby_annotation || has_guard_validation) {
                                    out.push(Violation {
                                        rule_no: 11,
                                        rule_name: "Plausibility Checks".into(),
                                        line: *line,
                                        reason: format!(
                                            "Use of sensitive value '{}' without plausibility validation",
                                            utils::expr_text(value)
                                        ),
                                        suggestion: "Add a nearby @PlausibilityCheck or guard with range/authorization before this use.".into(),
                                    });
                                }
                            }
                            Mode::Enforcement => {
                                if has_nearby_annotation || has_guard_validation {
                                    let gated = guard_enforces(&guards_text, value, target_name)
                                        || utils::has_plausibility_annotation_above(*line, 1);
                                    if !gated {
                                        out.push(Violation {
                                            rule_no: 12,
                                            rule_name: "Plausibility Checks".into(),
                                            line: *line,
                                            reason: format!(
                                                "Plausibility present but not enforced before assigning '{}'",
                                                target_name
                                            ),
                                            suggestion: "Use the plausibility result to gate this action (e.g., IF setpointOK THEN assign).".into(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Statement::IfStmt { then_branch, else_branch, .. } => {
                walk(then_branch, out, mode);
                walk(else_branch, out, mode);
            }
            Statement::CaseStmt { cases, else_branch, .. } => {
                for (_, body) in cases { walk(body, out, mode); }
                walk(else_branch, out, mode);
            }
            _ => {}
        }
    }
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

fn is_sensitive_sink(target: &str) -> bool {
    let t = target.to_ascii_uppercase();
    t.contains("MOTOR")
        || t.contains("SPEED")
        || t.contains("SETPOINT")
        || t.contains("POSITION")
        || t.contains("CMD")
        || t.contains("COMMAND")
        || t.contains("OUTPUT")
}

fn guard_validates_value(guards: &str, value_expr: &Expression) -> bool {
    if guards.is_empty() { return false; }
    let g = guards.replace(' ', "").to_ascii_uppercase();
    let val_txt = utils::expr_text(value_expr).replace(' ', "").to_ascii_uppercase();
    let mentions = g.contains(&val_txt);
    let cmp      = g.contains("<=") || g.contains(">=") || g.contains('<') || g.contains('>');
    let rng_kw   = g.contains("LIMIT") || g.contains("BOUND") || g.contains("RANGE")
        || g.contains("MIN") || g.contains("MAX");
    let nonzero  = g.contains("!=0") || g.contains("<>0");
    (mentions && (cmp || nonzero)) || rng_kw
}

fn guard_enforces(guards: &str, value_expr: &Expression, target: &str) -> bool {
    if guards.is_empty() { return false; }
    let g = guards.to_ascii_uppercase();
    let val = utils::expr_text(value_expr).to_ascii_uppercase();
    let tgt = target.to_ascii_uppercase();
    let mentions_val  = g.contains(&val);
    let mentions_flag = g.contains("OK") || g.contains("VALID") || g.contains("AUTHORIZED");
    let mentions_tgt  = g.contains(&tgt);
    (mentions_val && mentions_flag) || (mentions_flag && mentions_tgt)
}
