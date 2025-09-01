//! Simplified parser for Instruction List (IL / AWL).
//! Translates accumulator-based logic (LD/ADD/ST) into the unified AST.

use std::{collections::HashMap, fs};
use std::path::Path;
use crate::ast::{BinOp, Expression, Function, FunctionKind, Program, Statement, UnaryOp};

pub fn parse_il(path: &Path) -> Result<Program, String> {
    let src = fs::read_to_string(path).map_err(|e| format!("read error: {e}"))?;
    parse_il_from_str(&src)
}

pub fn parse_il_from_str(src: &str) -> Result<Program, String> {
    // This is a more advanced parser that handles labels and jumps.
    // It's still simplified and won't handle all IL complexities.
    let lines: Vec<&str> = src.lines().collect();
    let labels = find_labels(&lines);

    let statements = parse_statements_from_il(&lines, &labels, 0, lines.len())?;

    let main_func = Function {
        name: "IL_Program".to_string(),
        kind: FunctionKind::Program,
        statements,
        line: 1,
    };

    Ok(Program { functions: vec![main_func] })
}

fn find_labels(lines: &[&str]) -> HashMap<String, usize> {
    let mut labels = HashMap::new();
    for (i, line) in lines.iter().enumerate() {
        if line.trim().ends_with(':') {
            let label = line.trim().trim_end_matches(':').to_string();
            labels.insert(label, i);
        }
    }
    labels
}

fn parse_statements_from_il(
    lines: &[&str],
    labels: &HashMap<String, usize>,
    start: usize,
    end: usize,
) -> Result<Vec<Statement>, String> {
    let mut stmts = Vec::new();
    let mut current_result: Option<Expression> = None;
    let mut i = start;

    while i < end {
        let line = lines[i].trim();
        let line_no = i + 1;

        if line.is_empty() || line.starts_with("//") || line.ends_with(':') {
            i += 1;
            continue;
        }

        let mut parts = line.split_whitespace();
        let instruction = parts.next().unwrap_or("").to_uppercase();
        let operand_str = parts.next();

        match instruction.as_str() {
            "LD" | "LDN" => {
                if let Some(op) = operand_str {
                    let expr = parse_operand(op, line_no);
                    current_result = if instruction == "LDN" {
                        Some(Expression::UnaryOp { op: UnaryOp::Not, expr: Box::new(expr), line: line_no })
                    } else {
                        Some(expr)
                    };
                }
            }
            "ST" => {
                if let (Some(target_var), Some(value_expr)) = (operand_str, current_result.take()) {
                    let stmt = Statement::Assign {
                        target: Expression::VariableRef(target_var.to_string()),
                        value: value_expr,
                        line: line_no,
                    };
                    stmts.push(stmt);
                }
            }
            "JMPC" | "JMPNC" => {
                if let (Some(label), Some(condition)) = (operand_str, current_result.take()) {
                    let target_line = *labels.get(label).unwrap_or(&end);
                    let (then_branch, next_i) = if instruction == "JMPC" {
                        (parse_statements_from_il(lines, labels, i + 1, target_line)?, target_line)
                    } else {
                        (vec![], i + 1) // JMPNC skips the next block
                    };
                    let else_branch = if instruction == "JMPNC" {
                        parse_statements_from_il(lines, labels, i + 1, target_line)?
                    } else {
                        vec![]
                    };

                    stmts.push(Statement::IfStmt { condition, then_branch, else_branch, line: line_no });
                    i = next_i;
                    continue;
                }
            }
            "JMP" => {
                if let Some(label) = operand_str {
                    i = *labels.get(label).unwrap_or(&i); // Unconditional jump
                }
            }
            _ => { // Handle arithmetic
                if let (Some(right_op), Some(left_expr)) = (operand_str, current_result.take()) {
                    if let Some(op_kind) = get_binop(&instruction) {
                        current_result = Some(Expression::BinaryOp {
                            op: op_kind,
                            left: Box::new(left_expr),
                            right: Box::new(parse_operand(right_op, line_no)),
                            line: line_no,
                        });
                    } else {
                        current_result = Some(left_expr); // Not an op we handle, pass through
                    }
                }
            }
        }
        i += 1;
    }
    Ok(stmts)
}

fn get_binop(s: &str) -> Option<BinOp> {
    match s {
        "ADD" => Some(BinOp::Add),
        "SUB" => Some(BinOp::Sub),
        "MUL" => Some(BinOp::Mul),
        "DIV" => Some(BinOp::Div),
        "AND" | "ANDN" => Some(BinOp::And),
        "OR" | "ORN" => Some(BinOp::Or),
        "EQ" => Some(BinOp::Eq),
        "GE" => Some(BinOp::Ge),
        "GT" => Some(BinOp::Gt),
        "LE" => Some(BinOp::Le),
        "LT" => Some(BinOp::Lt),
        _ => None,
    }
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