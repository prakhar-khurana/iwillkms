//! Security rule orchestrator and shared types.

use std::fs;
use std::path::Path;

use crate::ast::Program;

pub mod policy;
pub mod rule1;
pub mod rule2;
pub mod rule4;
pub mod rule5;
pub mod rule6;
pub mod rule7;
pub mod rule8;
pub mod rule9;
pub mod rule10;
pub mod rule11_12;
pub mod rule15;
pub mod rule16;
pub mod rule17;
pub mod rule18;
pub mod rule19;
pub mod rule20;
pub mod utils;

pub use policy::Policy;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Violation {
    pub rule_no: u8,
    pub rule_name: &'static str,
    pub line: usize,
    pub reason: String,
    pub suggestion: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WasmRuleResult {
    pub status: String, // "OK" or "NOT FOLLOWED"
    pub rule_no: u8,
    pub rule_name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violation: Option<Violation>,
}

#[derive(Debug, Clone)]
pub struct RuleResult {
    pub ok: bool,
    pub violations: Vec<Violation>,
}

impl RuleResult {
    pub fn ok(_rule_no: u8, _name: &'static str) -> Self {
        Self { ok: true, violations: vec![] }
    }
    pub fn violations(v: Vec<Violation>) -> Self {
        Self { ok: v.is_empty(), violations: v }
    }
}

pub fn load_policy(policy_path: Option<&Path>) -> Result<Policy, String> {
    if let Some(p) = policy_path {
        match fs::read_to_string(p) {
            Ok(s) => serde_json::from_str(&s).map_err(|e| format!("Invalid policy JSON: {}", e)),
            Err(e) => Err(format!("Could not read policy file: {}", e)),
        }
    } else {
        Ok(Policy::default())
    }
}

/// Run all rules and print in the exact required format.
pub fn run_all(program: &Program, policy: &Policy) {
    macro_rules! print_res {
        ($no:expr, $name:expr, $res:expr) => {{
            if $res.ok {
                println!("##Rule {}: {} -- OK", $no, $name);
            } else {
                for v in $res.violations {
                    println!(
                        "##Rule {}: {} -- NOT FOLLOWED--Line {}: {} {}",
                        v.rule_no,
                        v.rule_name,
                        v.line,
                        v.reason,
                        v.suggestion
                    );
                }
            }
        }};
    }

    print_res!(1,  "Modularize PLC Code", rule1::check(program));
    print_res!(2,  "Track operating modes", rule2::check(program));
    print_res!(4,  "Use PLC flags as integrity checks", rule4::check(program));
    print_res!(5,  "Use checksum integrity checks", rule5::check(program));
    print_res!(6,  "Validate timers and counters", rule6::check(program));
    print_res!(7,  "Validate paired inputs/outputs", rule7::check(program, policy));
    print_res!(8,  "Validate HMI input variables", rule8::check(program));
    print_res!(9,  "Validate indirections", rule9::check(program));
    print_res!(10, "Assign designated register blocks", rule10::check(program, policy));
    print_res!(11, "Plausibility Checks", rule11_12::check_rule11(program));
    print_res!(12, "Plausibility Checks", rule11_12::check_rule12(program)); // combined
    print_res!(15, "Define a safe restart state", rule15::check(program));
    print_res!(16, "Summarize PLC cycle times", rule16::check(program));
    print_res!(17, "Log PLC uptime", rule17::check(program));
    print_res!(18, "Log PLC hard stops", rule18::check(program));
    print_res!(19, "Monitor PLC memory usage", rule19::check(program));
    print_res!(20, "Trap false alerts", rule20::check(program));
}

pub fn run_all_for_wasm(program: &Program, policy: &Policy) -> Vec<WasmRuleResult> {
    let mut all_results = Vec::new();

    macro_rules! check_and_collect {
        ($no:expr, $name:expr, $check_fn:expr) => {
            let result = $check_fn;
            if result.ok {
                all_results.push(WasmRuleResult {
                    status: "OK".to_string(),
                    rule_no: $no,
                    rule_name: $name,
                    violation: None,
                });
            } else {
                // If there are multiple violations for one rule, create a result for each
                for v in result.violations {
                    all_results.push(WasmRuleResult {
                        status: "NOT FOLLOWED".to_string(),
                        rule_no: v.rule_no,
                        rule_name: v.rule_name,
                        violation: Some(v),
                    });
                }
            }
        };
    }
    check_and_collect!(1, "Modularize PLC Code", rule1::check(program));
    check_and_collect!(2, "Track operating modes", rule2::check(program));
    check_and_collect!(4, "Use PLC flags as integrity checks", rule4::check(program));
    check_and_collect!(5, "Use checksum integrity checks", rule5::check(program));
    check_and_collect!(6, "Validate timers and counters", rule6::check(program));
    check_and_collect!(7, "Validate paired inputs/outputs", rule7::check(program, policy));
    check_and_collect!(8, "Validate HMI input variables", rule8::check(program));
    check_and_collect!(9, "Validate indirections", rule9::check(program));
    check_and_collect!(10, "Assign designated register blocks", rule10::check(program, policy));
    check_and_collect!(11, "Plausibility Checks", rule11_12::check_rule11(program));
    check_and_collect!(12, "Plausibility Checks", rule11_12::check_rule12(program)); // combined
    check_and_collect!(15, "Define a safe restart state", rule15::check(program));
    check_and_collect!(16, "Summarize PLC cycle times", rule16::check(program));
    check_and_collect!(17, "Log PLC uptime", rule17::check(program)); 
    check_and_collect!(18, "Log PLC hard stops", rule18::check(program));
    check_and_collect!(19, "Monitor PLC memory usage", rule19::check(program));
    check_and_collect!(20, "Trap false alerts", rule20::check(program));
    
    all_results
} 
