//! Rule 20: Trap false alerts.
//! For any variable named `Critical_Alert_*`, verify existence/usage of
//! `Critical_Alert_*_False_Negative` and `_False_Positive`.

use crate::ast::{Program, Statement};
use super::{RuleResult, Violation};

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];

    for f in &program.functions {
        // Gather names seen
        let mut names: Vec<String> = vec![];
        let mut lines: Vec<(String, usize)> = vec![];
        collect_names(&f.statements, &mut names, &mut lines);

        for (name, ln) in lines {
            if let Some(prefix) = name.strip_prefix("Critical_Alert_") {
                let fn_var = format!("Critical_Alert_{}_False_Negative", prefix);
                let fp_var = format!("Critical_Alert_{}_False_Positive", prefix);

                let has_fn = names.iter().any(|n| n == &fn_var);
                let has_fp = names.iter().any(|n| n == &fp_var);

                if !(has_fn && has_fp) {
                    violations.push(Violation {
                        rule_no: 20,
                        rule_name: "Trap false alerts",
                        line: ln,
                        reason: format!("Missing trap variables '{}' or '{}'", fn_var, fp_var),
                        suggestion: "Implement self-checking pattern with both false-negative and false-positive traps.".into(),
                    });
                }
            }
        }
    }

    RuleResult::violations(violations)
}

fn collect_names(stmts: &[Statement], names: &mut Vec<String>, lines: &mut Vec<(String, usize)>) {
    for st in stmts {
        match st {
            Statement::Assign { target, line, .. } => {
                if !names.contains(&target.name) {
                    names.push(target.name.clone());
                }
                lines.push((target.name.clone(), *line));
            }
            Statement::IfStmt { then_branch, else_branch, .. } => {
                collect_names(then_branch, names, lines);
                collect_names(else_branch, names, lines);
            }
            Statement::Call { name, line, .. } => {
                if !names.contains(name) {
                    names.push(name.clone());
                }
                lines.push((name.clone(), *line));
            }
            _ => {}
        }
    }
}
