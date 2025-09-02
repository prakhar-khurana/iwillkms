// rule7.rs
use crate::ast::{Program, Statement, Expression};
use crate::rules::policy::Policy;
use crate::rules::{RuleResult, Violation};

/// Rule 7: Validate paired inputs/outputs
pub fn check(program: &Program, policy: &Policy) -> RuleResult {
    let mut violations = Vec::new();

    for func in &program.functions {
        let mut true_assignments: Vec<(&str, usize)> = Vec::new();
        for stmt in &func.statements {
            if let Statement::Assign { target, value, line } = stmt {
                if let Expression::BoolLiteral(val, _) = value {
                    if *val {
                        if let Expression::Identifier(name) = target {
                            true_assignments.push((name.as_str(), *line));
                        }
                    }
                }
            }
        }

        for pair in policy.pairs.iter().flatten() {
            let a = &pair[0];
            let b = &pair[1];

            let mut a_found_line: Option<usize> = None;
            let mut b_found_line: Option<usize> = None;

            // Use two separate checks instead of if/else-if to find both items
            for (name, line) in &true_assignments {
                if *name == a.as_str() {
                    a_found_line = Some(*line);
                }
                if *name == b.as_str() {
                    b_found_line = Some(*line);
                }
            }

            if let (Some(line1), Some(_)) = (a_found_line, b_found_line) {
                violations.push(Violation {
                    rule_no: 7,
                    rule_name: "Validate paired inputs/outputs",
                    // Report the line of the first variable in the pair
                    line: line1,
                    reason: format!("Paired outputs {} and {} both set to TRUE", a, b),
                    suggestion: "Add mutual exclusion logic (e.g., IF/ELSE) to prevent both outputs being active".into(),
                });
            }
        }
    }
    
    RuleResult::violations(violations)
}