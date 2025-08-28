//! Simplified parser for Instruction List (IL / AWL).
//! Translates accumulator-based logic (LD/ADD/ST) into the unified AST.

use std::fs;
use std::path::Path;
use crate::ast::{BinOp, Expression, Function, FunctionKind, Program, Statement, Variable};

pub fn parse_il(path: &Path) -> Result<Program, String> {
    let src = fs::read_to_string(path).map_err(|e| format!("read error: {e}"))?;
    parse_il_from_str(&src)
}

pub fn parse_il_from_str(src: &str) -> Result<Program, String> {
    let mut program = Program { functions: vec![] };

    // Assume a single function block for simplicity in this example.
    let mut current_func = Function {
        name: "IL_Program".to_string(),
        kind: FunctionKind::FC, // Or detect from source
        statements: vec![],
        line: 1,
    };

    // The "accumulator" or Current Result (CR) of the PLC.
    let mut current_result: Option<Expression> = None;

    for (i, line_raw) in src.lines().enumerate() {
        let line = line_raw.trim();
        let line_no = i + 1;

        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        let mut parts = line.split_whitespace();
        let instruction = parts.next().unwrap_or("").to_uppercase();
        let operand = parts.next().map(|s| s.to_string());

        match instruction.as_str() {
            "LD" => { // Load value into the accumulator
                if let Some(op) = operand {
                    current_result = Some(parse_operand(&op, line_no));
                }
            }
            "ST" => { // Store accumulator value into a variable
                if let (Some(target_var), Some(value_expr)) = (operand, current_result.take()) {
                    let stmt = Statement::Assign {
                        target: Expression::VariableRef(target_var),
                        value: value_expr,
                        line: line_no,
                    };
                    current_func.statements.push(stmt);
                }
            }
            "ADD" | "SUB" | "MUL" | "DIV" => {
                if let (Some(right_op), Some(left_expr)) = (operand, current_result.take()) {
                    let op_kind = match instruction.as_str() {
                        "ADD" => BinOp::Add,
                        "SUB" => BinOp::Sub,
                        "MUL" => BinOp::Mul,
                        _ => BinOp::Div,
                    };

                    let new_expr = Expression::BinaryOp {
                        op: op_kind,
                        left: Box::new(left_expr),
                        right: Box::new(parse_operand(&right_op, line_no)),
                        line: line_no,
                    };
                    current_result = Some(new_expr);
                }
            }
            // Other IL instructions like JMP, CAL, etc., could be added here.
            _ => {}
        }
    }

    program.functions.push(current_func);
    Ok(program)
}

/// Helper to parse an operand into a literal or a variable reference.
fn parse_operand(op: &str, line: usize) -> Expression {
    if let Ok(num) = op.parse::<i64>() {
        Expression::NumberLiteral(num, line)
    } else if op.eq_ignore_ascii_case("TRUE") {
        Expression::BoolLiteral(true, line)
    } else if op.eq_ignore_ascii_case("FALSE") {
        Expression::BoolLiteral(false, line)
    } else {
        Expression::VariableRef(op.to_string())
    }
}