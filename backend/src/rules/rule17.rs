// rule17.rs
use crate::ast::{Expression, Program, Statement};
use super::{RuleResult, Violation, utils::expr_text};

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];
    
    // These flags should be for the whole program, not per-function
    let mut has_sfc6 = false;
    let mut sfc6_line = None;
    let mut monotonic_uptime = false;
    let mut uptime_reported = false;
    let mut first_line = 0;

    for f in &program.functions {
        if first_line == 0 { first_line = f.line; }
        // First pass: detect SFC6/RD_SINFO and monotonic counter in this function
        for st in &f.statements {
            match st {
                Statement::Call { name, line, .. } => {
                    let up = name.to_ascii_uppercase();
                    if up.contains("SFC6") || up.contains("RD_SINFO") {
                        has_sfc6 = true;
                        sfc6_line = Some(*line);
                    }
                }
                Statement::Assign { target, value, .. } => {
                    if let Expression::Identifier(target_name) = target {
                        let tgt = target_name.to_ascii_uppercase();
                        let vtxt = expr_text(value).to_ascii_uppercase();
                        if tgt.contains("UPTIME") && vtxt.contains("UPTIME") && vtxt.contains("+") {
                            monotonic_uptime = true;
                        }
                    }
                }
                _ => {}
            }
        }

        // Second pass: detect reporting to HMI/DB/LOG
        for st in &f.statements {
            if let Statement::Assign { target, value, .. } = st {
                if let Expression::Identifier(target_name) = target {
                    let tgt = target_name.to_ascii_uppercase();
                    let vtxt = expr_text(value).to_ascii_uppercase();
                    if (tgt.contains("HMI") || tgt.contains("DB") || tgt.contains("LOG"))
                        && (vtxt.contains("UPTIME") || vtxt.contains("SFC6") || vtxt.contains("RD_SINFO") || vtxt.contains("RUNTIME"))
                    {
                        uptime_reported = true;
                        break;
                    }
                }
            }
        }
    }

    // Decide after checking all functions
    if has_sfc6 {
        if !uptime_reported {
            violations.push(Violation {
                rule_no: 17,
                rule_name: "Log PLC uptime",
                line: sfc6_line.unwrap_or(first_line),
                reason: "SFC6/RD_SINFO used but uptime not reported".into(),
                suggestion: "Assign SFC6/RD_SINFO runtime to an HMI/DB tag for monitoring.".into(),
            });
        }
    } else if !(monotonic_uptime && uptime_reported) { // If SFC6 path fails, check monotonic path
        violations.push(Violation {
            rule_no: 17,
            rule_name: "Log PLC uptime",
            line: first_line,
            reason: "No monotonic uptime logging detected".into(),
            suggestion: "Add an uptime counter (monotonic) and periodically store/log it to HMI/DB.".into(),
        });
    }

    RuleResult::violations(violations)
}