//! Rule 19: Monitor PLC memory usage.
//! Require a pipeline of: read (e.g., SFC24/TEST_DB) + compare (threshold) + emit (HMI/DB/LOG).

use crate::ast::{Expression, Program, Statement};
use super::{RuleResult, Violation, utils::expr_text};

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];

    let mut found_any_read = false;
    let mut first_line = 0;

    for f in &program.functions {
        if first_line == 0 { first_line = f.line; }
        let mut read = None;      // line of SFC24/TEST_DB
        let mut compare = false;  // seen comparison on memory-related values
        let mut emit = false;     // assigned to HMI/DB/LOG

        // Scan recursively
        scan(&f.statements, &mut read, &mut compare, &mut emit);

        if read.is_some() {
            found_any_read = true;
            if !(compare && emit) {
                violations.push(Violation {
                    rule_no: 19,
                    rule_name: "Monitor PLC memory usage",
                    line: read.unwrap(),
                    reason: "Memory usage read but not compared and/or emitted".into(),
                    suggestion: "Compare memory usage to thresholds and log/assign to HMI/DB.".into(),
                });
            }
        }
    }

    if !found_any_read {
            violations.push(Violation {
                rule_no: 19,
                rule_name: "Monitor PLC memory usage",
                line: first_line,
                reason: "No evidence of memory monitoring found.".into(),
                suggestion: "Implement memory monitoring (e.g., using SFC24/TEST_DB) to prevent overflows.".into(),
            });
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
                if let Expression::Identifier(target_name) = target {
                    let tgt = target_name.to_ascii_uppercase();
                    let vtxt = expr_text(value).to_ascii_uppercase();
                    if (tgt.contains("HMI") || tgt.contains("DB") || tgt.contains("LOG"))
                        && (vtxt.contains("SFC24") || vtxt.contains("TEST_DB") || vtxt.contains("MEM"))
                    {
                        *emit = true;
                    }
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
