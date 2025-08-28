//! Rule 19: Monitor PLC memory usage.
//! Heuristic: look for SFC24 (TEST_DB) or similar and ensure values are reported.

use crate::ast::{Program, Statement}; // Cleaned up use statements
use super::{RuleResult, Violation, utils::expr_text}; // Import the central utility

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];

    for f in &program.functions {
        let mut mem_call_line = None;
        for st in &f.statements {
            if let Statement::Call { name, line, .. } = st {
                let up = name.to_ascii_uppercase();
                if up.contains("SFC24") || up.contains("TEST_DB") {
                    mem_call_line = Some(*line);
                }
            }
        }
        if let Some(ln) = mem_call_line {
            let mut reported = false;
            for st in &f.statements {
                if let Statement::Assign { target, value, .. } = st {
                    let tgt = target.name.to_ascii_uppercase();
                    let vtxt = expr_text(value).to_ascii_uppercase();
                    if (tgt.contains("HMI") || tgt.contains("MEM") || tgt.contains("DB"))
                        && (vtxt.contains("SFC24") || vtxt.contains("TEST_DB"))
                    {
                        reported = true;
                        break;
                    }
                }
            }
            if !reported {
                violations.push(Violation {
                    rule_no: 19,
                    rule_name: "Monitor PLC memory usage",
                    line: ln,
                    reason: "SFC24/TEST_DB used but memory usage not reported".into(),
                    suggestion: "Assign memory usage data to an HMI/DB tag for monitoring.".into(),
                });
            }
        }
    }

    RuleResult::violations(violations)
}

// The local expr_text function has been removed.