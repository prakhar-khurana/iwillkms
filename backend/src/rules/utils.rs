// Replaced File

//! Shared utility functions for security rules.

use crate::ast::{Expression, BinOp, UnaryOp};
use std::sync::Mutex;
use once_cell::sync::Lazy;

// --- Globals for Context ---
static SOURCE_LINES: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::new()));

/// Caches the source code lines for context-aware checks.
pub fn set_source_lines(source: &str) {
    let mut handle = SOURCE_LINES.lock().unwrap();
    *handle = source.lines().map(String::from).collect();
}

/// Converts an AST Expression back into a string representation.
pub fn expr_text(e: &Expression) -> String {
    match e {
        Expression::NumberLiteral(n, _) => n.to_string(),
        Expression::BoolLiteral(b, _) => b.to_string().to_ascii_uppercase(),
        Expression::Identifier(s) => s.clone(),
        Expression::StringLiteral(s, _) => s.clone(), 
        Expression::UnaryOp { op, expr, .. } => {
            let op_str = match op { UnaryOp::Not => "NOT " };
            format!("{}{}", op_str, expr_text(expr))
        }
        Expression::BinaryOp { op, left, right, .. } => {
            let op_str = match op {
                BinOp::Add => "+", BinOp::Sub => "-", BinOp::Mul => "*", BinOp::Div => "/",
                BinOp::Eq => "=", BinOp::Neq => "<>", BinOp::Lt => "<", BinOp::Le => "<=",
                BinOp::Gt => ">", BinOp::Ge => ">=", BinOp::And => "AND", BinOp::Or => "OR",
                BinOp::Assign => ":=", // <-- CORRECTED: Added the missing match arm
            };
            format!("{} {} {}", expr_text(left), op_str, expr_text(right))
        }
        Expression::Index { base, index, .. } => {
            format!("{}[{}]", expr_text(base), expr_text(index))
        }
        Expression::FuncCall { name, args, .. } => {
            let arg_str = args.iter().map(|a| expr_text(a)).collect::<Vec<_>>().join(", ");
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