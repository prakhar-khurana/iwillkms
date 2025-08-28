//! Rule 1: Modularize PLC Code. Flag excessive cyclomatic complexity or
//! statement count in FC/FB/PROGRAM.

use crate::ast::{FunctionKind, Program, Statement};
use super::{RuleResult, Violation};

pub fn check(program: &Program) -> RuleResult {
    let mut violations = vec![];

    for f in &program.functions {
        if matches!(f.kind, FunctionKind::FC | FunctionKind::FB | FunctionKind::Program) {
            let complexity = cyclomatic_complexity(&f.statements);
            let count = statement_count(&f.statements);
            if complexity > 50 {
                violations.push(Violation {
                    rule_no: 1,
                    rule_name: "Modularize PLC Code",
                    line: f.line,
                    reason: format!("Cyclomatic complexity {} exceeds 50", complexity),
                    suggestion: "Split logic into smaller FC/FBs; reduce branching.".into(),
                });
            }
            if count > 500 {
                violations.push(Violation {
                    rule_no: 1,
                    rule_name: "Modularize PLC Code",
                    line: f.line,
                    reason: format!("Statement count {} exceeds 500", count),
                    suggestion: "Refactor large routines into smaller units.".into(),
                });
            }
        }
    }

    RuleResult::violations(violations)
}

fn cyclomatic_complexity(stmts: &[Statement]) -> usize {
    // Base complexity 1 + branches
    1 + count_branches(stmts)
}

fn count_branches(stmts: &[Statement]) -> usize {
    count_branches_with_depth(stmts, 0)
}

fn count_branches_with_depth(stmts: &[Statement], depth: usize) -> usize {
    if depth > 100 {  // Prevent stack overflow
        return 0;
    }
    
    let mut c = 0usize;
    for st in stmts {
        match st {
            Statement::IfStmt { then_branch, else_branch, .. } => {
                c += 1;
                c += count_branches_with_depth(then_branch, depth + 1);
                if !else_branch.is_empty() {
                    c += count_branches_with_depth(else_branch, depth + 1);
                }
            }
            Statement::CaseStmt { cases, else_branch, .. } => {
                c += cases.len();
                if !else_branch.is_empty() {
                    c += 1;
                }
                for (_, branch) in cases {
                    c += count_branches_with_depth(branch, depth + 1);
                }
                c += count_branches_with_depth(else_branch, depth + 1);
            }
            _ => {}
        }
    }
    c
}
fn statement_count(stmts: &[Statement]) -> usize {
    let mut n = 0usize;
    for st in stmts {
        n += 1;
        match st {
            Statement::IfStmt { then_branch, else_branch, .. } => {
                n += statement_count(then_branch);
                n += statement_count(else_branch);
            }
            Statement::CaseStmt { cases, else_branch, .. } => {
               for (_, branch) in cases {
                   n += statement_count(branch);
               }
               n += statement_count(else_branch);
            }
            _ => {}
        }
    }
    n
}