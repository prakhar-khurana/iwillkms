//! Simplified parser for Structured Control Language (SCL / ST).
//! This is a placeholder demonstrating how to handle complex assignments.
//! A real-world implementation would use a proper parsing library like `pest` or `nom`.

use std::fs;
use std::path::Path;
use crate::ast::{Program, Function, FunctionKind, Statement, Expression, BinOp};

pub fn parse_scl(path: &Path) -> Result<Program, String> {
    let src = fs::read_to_string(path).map_err(|e| format!("read error: {e}"))?;
    parse_scl_from_str(&src)
}

pub fn parse_scl_from_str(src: &str) -> Result<Program, String> {
    // This is a very basic, line-by-line "parser" for demonstration.
    // It does not build a proper AST with nested control flow, but it correctly
    // handles the `target` of an assignment as an `Expression`.

    let mut statements = Vec::new();
    let mut line_no = 0;

    for line in src.lines() {
        line_no += 1;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }

        // Look for an assignment statement
        if let Some(idx) = trimmed.find(":=") {
            let (target_str, value_str) = trimmed.split_at(idx);
            let value_str = value_str[2..].trim().trim_end_matches(';');

            // The key fix: The left-hand side is parsed as a full expression,
            // allowing for `MyVar` as well as `MyArray[i]`.
            let target_expr = parse_scl_expression(target_str.trim(), line_no);
            let value_expr = parse_scl_expression(value_str, line_no);

            statements.push(Statement::Assign {
                target: target_expr,
                value: value_expr,
                line: line_no,
            });
        } else if trimmed.to_ascii_uppercase().contains("STRCPY") {
            // Simplified unsafe call detection
            statements.push(Statement::Call {
                name: "STRCPY".to_string(),
                args: vec![],
                line: line_no,
            });
        }
    }

    let main_func = Function {
        name: "SCL_Program".to_string(),
        kind: FunctionKind::Program,
        statements,
        line: 1,
    };

    Ok(Program { functions: vec![main_func] })
}

/// A minimal expression parser for the demo.
fn parse_scl_expression(s: &str, line: usize) -> Expression {
    // Check for array indexing: `MyArray[i]`
    if let Some(start) = s.find('[') {
        if let Some(end) = s.rfind(']') {
            let base_str = &s[..start];
            let index_str = &s[start+1..end];
            return Expression::Index {
                base: Box::new(Expression::VariableRef(base_str.to_string())),
                index: Box::new(parse_scl_expression(index_str, line)),
                line,
            };
        }
    }

    // Check for division
    if let Some(idx) = s.find('/') {
        let (left_str, right_str) = s.split_at(idx);
        return Expression::BinaryOp {
            op: BinOp::Div,
            left: Box::new(parse_scl_expression(left_str.trim(), line)),
            right: Box::new(parse_scl_expression(right_str[1..].trim(), line)),
            line,
        };
    }

    // Check for literals
    if let Ok(num) = s.parse::<i64>() {
        return Expression::NumberLiteral(num, line);
    }
    if s.eq_ignore_ascii_case("TRUE") {
        return Expression::BoolLiteral(true, line);
    }
    if s.eq_ignore_ascii_case("FALSE") {
        return Expression::BoolLiteral(false, line);
    }

    // Default to a variable reference
    Expression::VariableRef(s.to_string())
}