// Replaced File

use crate::{rules::RuleResult, rules::Violation};
use crate::ast::{Expression, Program, Statement, BinOp};
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
        walk_statements(&f.statements, &mut vec![], &mut out, mode);
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

fn walk_statements<'a>(
    stmts: &'a [Statement],
    guards: &mut Vec<&'a Expression>,
    out: &mut Vec<Violation>,
    mode: Mode
) {
    for st in stmts {
        match st {
            Statement::Assign { target, value, line } => {
                if let Expression::Identifier(target_name) = target {
                    let sensitive_use = expr_has_sensitive_source(value);
                    let is_sink = is_sensitive_sink(target_name);

                    if sensitive_use && is_sink {
                        let has_nearby_annotation = utils::has_plausibility_annotation_above(*line, 3);
                        
                        let mut value_vars = HashSet::new();
                        collect_vars(value, &mut value_vars);
                        let has_guard_validation = is_guarded_by_range(&value_vars, guards);

                        match mode {
                            Mode::Presence => {
                                if !(has_nearby_annotation || has_guard_validation) {
                                    out.push(Violation {
                                        rule_no: 11,
                                        rule_name: "Plausibility Checks",
                                        line: *line,
                                        reason: format!("Use of sensitive value '{}' without plausibility validation", utils::expr_text(value)),
                                        suggestion: "Add a nearby @PlausibilityCheck or guard with range/authorization before this use.".into(),
                                    });
                                }
                            }
                            Mode::Enforcement => {
                                if has_nearby_annotation && !has_guard_validation {
                                     let gated = guard_enforces_flag(guards) || utils::has_plausibility_annotation_above(*line, 1);
                                     if !gated {
                                         out.push(Violation {
                                            rule_no: 12,
                                            rule_name: "Plausibility Checks",
                                            line: *line,
                                            reason: format!("Plausibility annotation present but not enforced before assigning to '{}'", target_name),
                                            suggestion: "Use the plausibility result to gate this action (e.g., IF setpointOK THEN ...).".into(),
                                         });
                                     }
                                }
                            }
                        }
                    }
                }
            }
            Statement::IfStmt { condition, then_branch, else_branch, .. } => {
                guards.push(condition);
                walk_statements(then_branch, guards, out, mode);
                guards.pop();
                walk_statements(else_branch, guards, out, mode);
            }
            Statement::CaseStmt { cases, else_branch, .. } => {
                for (_, body) in cases { walk_statements(body, guards, out, mode); }
                walk_statements(else_branch, guards, out, mode);
            }
            _ => {}
        }
    }
}

// Helper functions

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

fn is_sensitive_sink(target: &str) -> bool {
    let t = target.to_ascii_uppercase();
    t.contains("MOTOR") || t.contains("SPEED") || t.contains("SETPOINT") || t.contains("POSITION") || t.contains("CMD") || t.contains("COMMAND") || t.contains("OUTPUT")
}

fn is_guarded_by_range(vars: &HashSet<String>, guards: &[&Expression]) -> bool {
    vars.iter().any(|var| guards.iter().any(|guard| is_var_constrained(var, guard)))
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

// For Rule 12: checks if any guard is a simple flag like `VariableOK`
fn guard_enforces_flag(guards: &[&Expression]) -> bool {
    guards.iter().any(|g| {
        if let Expression::Identifier(name) = g {
            let up = name.to_ascii_uppercase();
            up.ends_with("OK") || up.ends_with("VALID") || up.contains("AUTHORIZED")
        } else {
            false
        }
    })
}