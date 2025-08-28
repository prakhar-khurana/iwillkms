//! Rule 10: Assign designated register blocks (policy-based RO regions)

use crate::ast::{Program, Statement};
use super::{Policy, RuleResult, Violation};

pub fn check(program: &Program, policy: &Policy) -> RuleResult {
    let mut violations = vec![];

    let areas = policy.memory_areas.as_ref().map(|v| v.as_slice()).unwrap_or(&[]);
    if areas.is_empty() {
        return RuleResult::ok(10, "Assign designated register blocks");
    }

    for func in &program.functions {
        for st in &func.statements {
            if let Statement::Assign { target, line, .. } = st {
                if let Some((area, addr)) = parse_mem_address(&target.name) {
                    for r in areas {
                        if r.access.to_ascii_lowercase() == "readonly" && r.applies(&area, addr) {
                            violations.push(Violation {
                                rule_no: 10,
                                rule_name: "Assign designated register blocks",
                                line: *line,
                                reason: format!("Write to read-only region {}{}", area, addr),
                                suggestion: "Move this write to an allowed area or update policy.json".into(),
                            });
                        }
                    }
                }
            }
        }
    }

    RuleResult::violations(violations)
}

// Very simple parser for addresses like %MW100, %DB1.DBX10.0, %M100 etc.
fn parse_mem_address(s: &str) -> Option<(String, i64)> {
    if !s.starts_with('%') {
        return None;
    }
    let mut area = String::new();
    let mut num = String::new();
    let mut seen_area = false;
    for ch in s.chars().skip(1) {
        if ch.is_ascii_alphabetic() {
            if !seen_area { area.push('%'); }
            area.push(ch);
            seen_area = true;
        } else if ch.is_ascii_digit() {
            num.push(ch);
        } else {
            if !num.is_empty() { break; }
        }
    }
    if area.len() > 1 && !num.is_empty() {
        if let Ok(n) = num.parse::<i64>() {
            return Some((area, n));
        }
    }
    None
}

trait Applies {
    fn applies(&self, area: &str, addr: i64) -> bool;
}

impl Applies for super::policy::MemoryArea {
    fn applies(&self, area: &str, addr: i64) -> bool {
        if !self.address.to_ascii_lowercase().starts_with(&area.to_ascii_lowercase()) {
            return false;
        }
        if let Some((start, end)) = self.range_bounds() {
            addr >= start && addr <= end
        } else {
            false
        }
    }
}

impl super::policy::MemoryArea {
    fn range_bounds(&self) -> Option<(i64, i64)> {
        let s = self.address.trim();
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 2 {
            let start = parts[0].chars().filter(|c| c.is_ascii_digit()).collect::<String>();
            let end = parts[1].chars().filter(|c| c.is_ascii_digit()).collect::<String>();
            if let (Ok(a), Ok(b)) = (start.parse::<i64>(), end.parse::<i64>()) {
                return Some((a, b));
            }
        }
        None
    }
}
