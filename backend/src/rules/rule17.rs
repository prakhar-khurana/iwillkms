//! Rule 17: Log PLC uptime.
//! Check for SFC6 (RD_SINFO) and ensure the runtime counter is reported.

use crate::ast::{Program, Statement}; // Cleaned up use statements
use super::{RuleResult, Violation, utils::expr_text}; // Import the central utility

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];

    for f in &program.functions {
        let mut sfc6_line = None;
        for st in &f.statements {
            if let Statement::Call { name, line, .. } = st {
                if name.to_ascii_uppercase().contains("SFC6") || name.to_ascii_uppercase().contains("RD_SINFO") {
                    sfc6_line = Some(*line);
                }
            }
        }
        if let Some(ln) = sfc6_line {
            let mut reported = false;
            for st in &f.statements {
                if let Statement::Assign { target, value, .. } = st {
                    let up = target.name.to_ascii_uppercase();
                    let vtxt = expr_text(value).to_ascii_uppercase();
                    if (up.contains("HMI") || up.contains("UPTIME")) && (vtxt.contains("SFC6") || vtxt.contains("RD_SINFO") || vtxt.contains("RUNTIME")) {
                        reported = true;
                        break;
                    }
                }
            }
            if !reported {
                violations.push(Violation {
                    rule_no: 17,
                    rule_name: "Log PLC uptime",
                    line: ln,
                    reason: "SFC6/RD_SINFO used but uptime not reported".into(),
                    suggestion: "Move uptime counter to an HMI tag or logging DB.".into(),
                });
            }
        }
    }

    RuleResult::violations(violations)
}

// The local expr_text function has been removed.