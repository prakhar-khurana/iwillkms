//! Rule 18: Log PLC hard stops.
//! Verify non-empty OB86 (Rack Failure), OB121 (Programming Error), OB82 (Diagnostic Interrupt).

use crate::ast::{FunctionKind, Program};
use super::{RuleResult, Violation};

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];

    fn non_empty(program: &Program, kind: FunctionKind) -> Option<usize> {
        program.functions.iter().find(|f| f.kind == kind && !f.statements.is_empty()).map(|f| f.line)
    }

    let ob86 = non_empty(program, FunctionKind::OB86);
    let ob121 = non_empty(program, FunctionKind::OB121);
    let ob82 = non_empty(program, FunctionKind::OB82);

    if ob86.is_none() {
        violations.push(Violation {
            rule_no: 18,
            rule_name: "Log PLC hard stops",
            line: 0,
            reason: "OB86 (Rack Failure) missing or empty".into(),
            suggestion: "Implement OB86 to log rack failures and take safe action.".into(),
        });
    }
    if ob121.is_none() {
        violations.push(Violation {
            rule_no: 18,
            rule_name: "Log PLC hard stops",
            line: 0,
            reason: "OB121 (Programming Error) missing or empty".into(),
            suggestion: "Implement OB121 to log and safely recover from programming errors.".into(),
        });
    }
    if ob82.is_none() {
        violations.push(Violation {
            rule_no: 18,
            rule_name: "Log PLC hard stops",
            line: 0,
            reason: "OB82 (Diagnostic Interrupt) missing or empty".into(),
            suggestion: "Implement OB82 to capture diagnostic interrupts.".into(),
        });
    }

    RuleResult::violations(violations)
}
