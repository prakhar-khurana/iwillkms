//! Rule 16: Summarize PLC cycle times.
//! Require OB1 to *capture* OB1_PREV_CYCLE and *emit* it to an HMI/DB/LOG tag.

use crate::ast::{Expression, FunctionKind, Program, Statement};
use super::{RuleResult, Violation, utils::expr_text};

pub fn check(program: &Program) -> RuleResult {
    let ob1 = program.functions.iter().find(|f| f.kind == FunctionKind::OB1);
    if let Some(f) = ob1 {
        // Scan recursively: capture (source) + emit (sink)
        let mut has_capture = false;
        let mut has_emit = false;
        scan(&f.statements, &mut has_capture, &mut has_emit);

        if has_capture && has_emit {
            RuleResult::ok(16, "Summarize PLC cycle times")
        } else {
            RuleResult::violations(vec![Violation {
                rule_no: 16,
                rule_name: "Summarize PLC cycle times",
                line: f.line,
                reason: "Cycle-time summary incomplete (capture+emit not both present)".into(),
                suggestion: "In OB1, move OB1_PREV_CYCLE into an HMI/DB/LOG tag (e.g., HMI_CycleTime := OB1_PREV_CYCLE).".into(),
            }])
        }
    } else {
        // No OB1? Treat as OK for portability (or change to WARN/NOT FOLLOWED per policy)
        RuleResult::ok(16, "Summarize PLC cycle times")
    }
}

fn scan(stmts: &[Statement], cap: &mut bool, emit: &mut bool) {
    for st in stmts {
        match st {
            Statement::Assign { target, value, .. } => {
                if let Expression::Identifier(target_name) = target {
                    let v = expr_text(value).to_ascii_uppercase();
                    let t = target_name.to_ascii_uppercase();
                    if v.contains("OB1_PREV_CYCLE") { *cap = true; }
                    if (t.contains("HMI") || t.contains("DB") || t.contains("LOG")) && v.contains("OB1_PREV_CYCLE") {
                        *emit = true;
                    }
                }
            }
            Statement::IfStmt { then_branch, else_branch, .. } => {
                scan(then_branch, cap, emit);
                scan(else_branch, cap, emit);
            }
            Statement::CaseStmt { cases, else_branch, .. } => {
                for (_, body) in cases { scan(body, cap, emit); }
                scan(else_branch, cap, emit);
            }
            _ => {}
        }
    }
}
