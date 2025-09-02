use crate::ast::{Program, Statement, Expression};
use crate::rules::policy::Policy;
use crate::rules::{RuleResult, Violation};

/// Rule 8: Validate HMI input variables
pub fn check(program: &Program, _policy: &Policy) -> RuleResult {
    let mut violations = Vec::new();

    fn expr_has_hmi(expr: &Expression) -> bool {
        match expr {
            Expression::Identifier(name) => name.to_uppercase().contains("HMI"),
            Expression::FuncCall { args, .. } => args.iter().any(expr_has_hmi),
            Expression::BinaryOp { left, right, .. } => expr_has_hmi(left) || expr_has_hmi(right),
            Expression::Index { base, index, .. } => expr_has_hmi(base) || expr_has_hmi(index),
            _ => false,
        }
    }

    for func in &program.functions {
        for stmt in &func.statements {
            if let Statement::Assign { target: _, value, line } = stmt {
                if expr_has_hmi(value) {
                    violations.push(Violation {
                        rule_no: 8,
                        rule_name: "Validate HMI input variables".into(),
                        line: *line,
                        reason: "HMI input variable used without plausibility checks".into(),
                        suggestion: "Add plausibility checks (range limits or comments) before assignment".into(),
                    });
                }
            }
        }
    }

    if violations.is_empty() {
        RuleResult::ok(8, "Validate HMI input variables")
    } else {
        RuleResult::violations(violations)
    }
}