//! Rule 20: Trap false alerts.
//! For each Critical_Alert_* signal, require existence *and usage* of
//! Critical_Alert_*_False_Negative and Critical_Alert_*_False_Positive.

use crate::ast::{Program, Statement, Expression};
use super::{RuleResult, Violation};
use std::collections::HashSet;

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];

    for f in &program.functions {
        let mut names = HashSet::new();
        let mut lines = vec![];
        collect_names(&f.statements, &mut names, &mut lines);

        for (name, ln) in lines {
            if let Some(prefix) = name.strip_prefix("Critical_Alert_") {
                if prefix.ends_with("_False_Negative") || prefix.ends_with("_False_Positive") {
                    continue;
                }
                let fn_var = format!("Critical_Alert_{}_False_Negative", prefix);
                let fp_var = format!("Critical_Alert_{}_False_Positive", prefix);

                let have_both = names.contains(&fn_var) && names.contains(&fp_var);
                let used_both = signal_used(&f.statements, &fn_var) && signal_used(&f.statements, &fp_var);

                if !(have_both && used_both) {
                    violations.push(Violation {
                        rule_no: 20,
                        rule_name: "Trap false alerts",
                        line: ln,
                        reason: format!("Missing or unused trap variables for '{}'", name),
                        suggestion: "Define and wire both *_False_Negative and *_False_Positive signals into logic/logs.".into(),
                    });
                }
            }
        }
    }

    RuleResult::violations(violations)
}

fn signal_used(stmts: &[Statement], signal: &str) -> bool {
    for st in stmts {
        match st {
            Statement::Assign { target, value, .. } => {
                if let Expression::Identifier(target_name) = target {
                    if target_name == signal { return true; }
                }
                if super::utils::expr_text(value).contains(signal) { return true; } // Check RHS
            }
            Statement::IfStmt { condition, then_branch, else_branch, .. } => {
                if super::utils::expr_text(condition).contains(signal) { return true; }
                if signal_used(then_branch, signal) || signal_used(else_branch, signal) { return true; }
            }
            // labels are Vec<Expression>; check each label's text
            Statement::CaseStmt { cases, else_branch, .. } => {
                for (labels, body) in cases {
                    if labels.iter().any(|e| super::utils::expr_text(e).contains(signal)) { return true; }
                    if signal_used(body, signal) { return true; }
                }
                if signal_used(else_branch, signal) { return true; }
            }
            Statement::Call { name, .. } => {
                if name == signal { return true; }
            }
            _ => {}
        }
    }
    false
}

fn collect_names(stmts: &[Statement], names: &mut HashSet<String>, lines: &mut Vec<(String, usize)>) {
    for st in stmts {
        match st {
            Statement::Assign { target, line, .. } => {
                if let Expression::Identifier(name) = target {
                    names.insert(name.clone());
                    lines.push((name.clone(), *line));
                }
            }
            Statement::IfStmt { then_branch, else_branch, .. } => {
                collect_names(then_branch, names, lines);
                collect_names(else_branch, names, lines);
            }
            Statement::CaseStmt { cases, else_branch, .. } => {
                for (_, body) in cases { collect_names(body, names, lines); }
                collect_names(else_branch, names, lines);
            }
            Statement::Call { name, line, .. } => {
                names.insert(name.clone());
                lines.push((name.clone(), *line));
            }
            _ => {}
        }
    }
}
