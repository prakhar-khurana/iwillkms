use crate::ast::{Program, Statement, Expression};
use crate::rules::policy::Policy;
use crate::rules::{RuleResult, Violation};

/// Rule 6: Validate timers and counters
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
            if let Statement::Call { name, args, line } = stmt {
                let lname = name.to_lowercase();
                if lname.contains("tp") || lname.contains("ton") || lname.contains("tof") {
                    for (_, arg_expr) in args {
                        if expr_has_hmi(arg_expr) {
                            violations.push(Violation {
                                rule_no: 6,
                                rule_name: "Validate timers and counters",
                                line: *line,
                                reason: "Timer preset sourced from HMI without plausibility check".into(),
                                suggestion: "Precede timer assignment with a numeric range check".into(),
                            });
                        }
                    }
                }
            }
        }
    }

    if violations.is_empty() {
        RuleResult::ok(6, "Validate timers and counters")
    } else {
        RuleResult::violations(violations)
    }
}
