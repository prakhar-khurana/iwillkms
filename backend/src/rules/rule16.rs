//! Rule 16: Summarize PLC cycle times.
//! Verify that if OB1 exists, it reads OB1_PREV_CYCLE and moves it to an HMI tag.

use crate::ast::{Program, Statement, FunctionKind}; // Cleaned up use statements
use super::{RuleResult, Violation, utils::expr_text}; // Import the central utility

pub fn check(program: &Program) -> RuleResult {
    let ob1 = program.functions.iter().find(|f| f.kind == FunctionKind::OB1);

    if let Some(f) = ob1 {
        let mut moved_to_hmi = false;
        for st in &f.statements {
            if let Statement::Assign { target, value, .. } = st {
                let val_txt = expr_text(value).to_ascii_uppercase();
                let tgt_txt = target.name.to_ascii_uppercase();
                
                if val_txt.contains("OB1_PREV_CYCLE") && (tgt_txt.contains("HMI") || tgt_txt.contains("CYCLE")) {
                    moved_to_hmi = true;
                    break;
                }
            }
        }

        if !moved_to_hmi {
            return RuleResult::violations(vec![Violation {
                rule_no: 16,
                rule_name: "Summarize PLC cycle times",
                line: f.line,
                reason: "Cycle time is not read from OB1_PREV_CYCLE and reported for monitoring".into(),
                suggestion: "In OB1, add logic like 'HMI_CycleTime := OB1_PREV_CYCLE;'.".into(),
            }]);
        }
    }

    RuleResult::ok(16, "Summarize PLC cycle times")
}

// The local expr_text function has been removed.