//! Rule 19: Monitor PLC memory usage.
//! Require a pipeline of: read (e.g., SFC24/TEST_DB) + compare (threshold) + emit (HMI/DB/LOG).

use crate::ast::{Program, Statement};
use super::{RuleResult, Violation, utils::expr_text};

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];

    for f in &program.functions {
        let mut read = None;      // line of SFC24/TEST_DB
        let mut compare = false;  // seen comparison on memory-related values
        let mut emit = false;     // assigned to HMI/DB/LOG

        // Scan recursively
        scan(&f.statements, &mut read, &mut compare, &mut emit);

        if read.is_some() && compare && emit {
            // OK for this function
        } else if read.is_some() {
            violations.push(Violation {
                rule_no: 19,
                rule_name: "Monitor PLC memory usage",
                line: read.unwrap(),
                reason: "Memory usage read without compare+emit".into(),
                suggestion: "Compare memory usage to thresholds and log/assign to HMI/DB.".into(),
            });
        }
    }

    RuleResult::violations(violations)
}

fn scan(stmts: &[Statement], read: &mut Option<usize>, compare: &mut bool, emit: &mut bool) {
    for st in stmts {
        match st {
            Statement::Call { name, line, .. } => {
                let up = name.to_ascii_uppercase();
                if up.contains("SFC24") || up.contains("TEST_DB") {
                    *read = Some(*line);
                }
            }
            Statement::Assign { target, value, .. } => {
                let tgt = target.name.to_ascii_uppercase();
                let vtxt = expr_text(value).to_ascii_uppercase();
                if (tgt.contains("HMI") || tgt.contains("DB") || tgt.contains("LOG"))
                    && (vtxt.contains("SFC24") || vtxt.contains("TEST_DB") || vtxt.contains("MEM"))
                {
                    *emit = true;
                }
            }
            Statement::IfStmt { condition, then_branch, else_branch, .. } => {
                let c = expr_text(condition).to_ascii_uppercase();
                if c.contains(">") || c.contains("<") || c.contains(">=") || c.contains("<=") {
                    if c.contains("SFC24") || c.contains("TEST_DB") || c.contains("MEM") || c.contains("%MW") || c.contains("%DB") {
                        *compare = true;
                    }
                }
                scan(then_branch, read, compare, emit);
                scan(else_branch, read, compare, emit);
            }
            Statement::CaseStmt { cases, else_branch, .. } => {
                for (_, body) in cases { scan(body, read, compare, emit); }
                scan(else_branch, read, compare, emit);
            }
            _ => {}
        }
    }
}
