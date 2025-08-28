use crate::ast::{Expression, Program, Statement};
use super::{Policy, RuleResult, Violation};
use std::collections::HashSet;

pub fn check(program: &Program, policy: &Policy) -> RuleResult {
    let mut violations = vec![];

    let Some(pairs) = &policy.pairs else {
        return RuleResult::ok(7, "Validate paired inputs/outputs");
    };
    if pairs.is_empty() {
        return RuleResult::ok(7, "Validate paired inputs/outputs");
    }

    for func in &program.functions {
        for pair in pairs {
            let initial_signals = HashSet::new();
            find_concurrent_activations(&func.statements, pair, initial_signals, &mut violations);
        }
    }

    RuleResult::violations(violations)
}

fn find_concurrent_activations(
    stmts: &[Statement],
    pair: &[String; 2],
    mut active_signals: HashSet<String>,
    violations: &mut Vec<Violation>,
) -> bool {
    let a_up = &pair[0].to_ascii_uppercase();
    let b_up = &pair[1].to_ascii_uppercase();
    let mut violation_found_in_path = false;

    for st in stmts {
        if violation_found_in_path { continue; } // Stop processing this path if violation found

        match st {
            Statement::Assign { target, value, line } => {
                let target_up = target.name.to_ascii_uppercase();
                let is_true = is_true_expr(value);

                if &target_up == a_up {
                    if is_true { active_signals.insert(a_up.clone()); } else { active_signals.remove(a_up); }
                } else if &target_up == b_up {
                    if is_true { active_signals.insert(b_up.clone()); } else { active_signals.remove(b_up); }
                }

                if active_signals.contains(a_up) && active_signals.contains(b_up) {
                    violations.push(Violation {
                        rule_no: 7,
                        rule_name: "Validate paired inputs/outputs",
                        line: *line,
                        reason: format!(
                            "Signals '{}' and '{}' may be active concurrently",
                            &pair[0], &pair[1]
                        ),
                        suggestion: "Ensure paired signals are in mutually exclusive conditions (e.g., using IF/ELSE).".into(),
                    });
                    violation_found_in_path = true;
                }
            }
            Statement::IfStmt { then_branch, else_branch, .. } => {
                // Each branch is checked independently with a clone of the current state.
                let then_violation = find_concurrent_activations(then_branch, pair, active_signals.clone(), violations);
                let else_violation = find_concurrent_activations(else_branch, pair, active_signals.clone(), violations);
                if then_violation || else_violation {
                    violation_found_in_path = true;
                }
            }
            _ => {}
        }
    }
    violation_found_in_path
}

fn is_true_expr(e: &Expression) -> bool {
    match e {
        Expression::BoolLiteral(true, _) => true,
        Expression::NumberLiteral(n, _) if *n != 0 => true,
        _ => false,
    }
}