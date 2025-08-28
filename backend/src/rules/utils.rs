//! Shared utility functions for security rules.

use crate::ast::{Expression, BinOp, UnaryOp};
use std::sync::Mutex;
use once_cell::sync::Lazy;

// --- Globals for Context ---
// In a real-world tool, passing context down the call stack is cleaner.
// But for this project structure, globals are a pragmatic way to give
// rules access to the full source code for comment/context-based checks.

static SOURCE_LINES: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::new()));

/// Caches the source code lines for context-aware checks.
/// This should be called once after the source file is read.
pub fn set_source_lines(source: &str) {
    let mut handle = SOURCE_LINES.lock().unwrap();
    *handle = source.lines().map(String::from).collect();
}

/// Converts an AST Expression back into a string representation.
/// Useful for simple, text-based checks in rule logic.
pub fn expr_text(e: &Expression) -> String {
    match e {
        Expression::NumberLiteral(n, _) => n.to_string(),
        Expression::BoolLiteral(b, _) => b.to_string().to_ascii_uppercase(),
        Expression::VariableRef(s) => s.clone(),
        Expression::UnaryOp { op, expr, .. } => {
            let op_str = match op { UnaryOp::Not => "NOT " };
            format!("{}{}", op_str, expr_text(expr))
        }
        Expression::BinaryOp { op, left, right, .. } => {
            let op_str = match op {
                BinOp::Add => "+", BinOp::Sub => "-", BinOp::Mul => "*", BinOp::Div => "/",
                BinOp::Eq => "=", BinOp::Neq => "<>", BinOp::Lt => "<", BinOp::Le => "<=",
                BinOp::Gt => ">", BinOp::Ge => ">=", BinOp::And => "AND", BinOp::Or => "OR",
            };
            format!("{} {} {}", expr_text(left), op_str, expr_text(right))
        }
        Expression::Index { base, index, .. } => {
            format!("{}[{}]", expr_text(base), expr_text(index))
        }
        Expression::FuncCall { name, args, .. } => {
            let arg_str = args.iter().map(expr_text).collect::<Vec<_>>().join(", ");
            format!("{}({})", name, arg_str)
        }
    }
}

/// Checks if a variable name suggests it's from a sensitive source like HMI or a recipe.
pub fn is_sensitive_variable(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    up.contains("HMI") || up.contains("RECIPE") || up.contains("PARAM") || up.contains("SETPOINT")
}

/// Looks for a `@PlausibilityCheck` annotation in comments above a given line.
pub fn has_plausibility_annotation_above(line: usize, search_depth: usize) -> bool {
    if line == 0 { return false; }
    let lines = SOURCE_LINES.lock().unwrap();
    let start = line.saturating_sub(search_depth).saturating_sub(1);
    let end = line.saturating_sub(1);

    lines.get(start..end).unwrap_or(&[]).iter().any(|l| {
        let up = l.to_ascii_uppercase();
        up.contains("@PLAUSIBILITYCHECK") || up.contains("@VALIDATION")
    })
}

/// **NOTE: This function represents a design flaw.**
/// It attempts to find the guard condition for a given line by searching the
/// source code. This is inefficient and brittle.
///
/// The **correct approach**, as implemented in `rule8.rs` and `rule9.rs`, is to
/// pass the guard conditions down the stack during the AST traversal.
///
/// This function is provided for compatibility with older rule implementations
/// (`rule6`, `rule11_12`) but should be considered for deprecation. The fix
/// is to refactor those rules to manage guard context internally.
pub fn current_guard_text(line: usize) -> String {
    if line == 0 { return String::new(); }
    let lines = SOURCE_LINES.lock().unwrap();
    let mut depth = 0;
    let mut guard = String::new();

    // Reverse search from the line upwards
    for i in (0..line.saturating_sub(1)).rev() {
        if let Some(l) = lines.get(i) {
            let up = l.to_ascii_uppercase();
            if up.contains("END_IF") { depth += 1; }
            if up.contains("IF ") {
                if depth == 0 {
                    // Found the immediate IF
                    if let Some(start) = up.find("IF ") {
                        if let Some(end) = up.rfind(" THEN") {
                            guard = up[start+3..end].trim().to_string();
                        }
                    }
                    break;
                } else {
                    depth -= 1;
                }
            }
        }
    }
    guard
}