//! Library crate for plc_secure_checker.
//!
//! This file simply re‑exports the modules used by the binary. The
//! library layout mirrors the organisation of the checker: the AST,
//! parsers and rule implementations all live under this crate root.

pub mod ast;
pub mod parser;
pub mod rules;
use wasm_bindgen::prelude::*;
use crate::rules::policy::parse_policy_from_text;
use crate::rules::Policy;

// This is the function that JavaScript will call
#[wasm_bindgen]
pub fn check_plc_code(source_code: &str, policy_json: &str, file_name: &str) -> String {
    // 1. Parse the PLC program using the appropriate frontend based on file_name
    let program = match parser::parse_file_from_str(source_code, file_name) {
        Ok(p) => p,
        Err(e) => {
            // Construct a sentinel error result if the PLC source fails to parse
            let err_result = vec![rules::WasmRuleResult {
                status: "ERROR".into(),
                rule_no: 0,
                rule_name: "Parse Error",
                violation: Some(rules::Violation {
                    rule_no: 0,
                    rule_name: "Parse Error",
                    line: 0,
                    reason: format!("Parse Error: {}", e),
                    suggestion: "Check file type and syntax.".into(),
                }),
            }];
            return serde_json::to_string(&err_result).unwrap_or_else(|_| "[]".into());
        }
    };

    // 2. Parse the custom policy JSON. If parsing fails, record an error and
    // continue with a default/empty policy to avoid crashing.
    let mut policy = Policy::default();
    // Collect any policy errors in a separate vector to prepend later
    let mut errors: Vec<rules::WasmRuleResult> = Vec::new();
    let trimmed_policy = policy_json.trim();
    if !trimmed_policy.is_empty() {
        match parse_policy_from_text(trimmed_policy) {
            Ok(p) => policy = p,
            Err(err) => {
                errors.push(rules::WasmRuleResult {
                    status: "ERROR".into(),
                    rule_no: 0,
                    rule_name: "Policy Parsing Error",
                    violation: Some(rules::Violation {
                        rule_no: 0,
                        rule_name: "Policy Parsing Error",
                        line: 0,
                        reason: err,
                        suggestion: "Fix policy JSON format. See About → Custom Policy example.".into(),
                    }),
                });
            }
        }
    }

    // 3. Run all rules using the parsed program and policy
    let mut results = rules::run_all_for_wasm(&program, &policy);
    // 4. If we have policy parsing errors, prepend them to the results
    if !errors.is_empty() {
        errors.append(&mut results);
        serde_json::to_string(&errors).unwrap_or_else(|_| "[]".into())
    } else {
        serde_json::to_string(&results).unwrap_or_else(|_| "[]".into())
    }
}