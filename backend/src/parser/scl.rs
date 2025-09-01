//! SCL parser implemented with Pest.
//! This parser consumes the parse tree generated from `scl.pest` and
//! builds the unified AST defined in `ast.rs`.

use std::fs;
use std::path::Path;
use pest::Parser;
use pest::iterators::{Pair, Pairs};
use pest::pratt_parser::{Assoc, Op, PrattParser};
use lazy_static::lazy_static;

use crate::ast::{Program, Function, FunctionKind, Statement, Expression, BinOp, UnaryOp};

#[derive(pest_derive::Parser)]
#[grammar = r"C:\Users\z005653n\Desktop\plc_practices_checker-master\backend\src\parser\scl.pest"]
struct SCLParser;

// Operator precedence parser for expressions.
lazy_static! {
    static ref PRATT_PARSER: PrattParser<Rule> = {
        use Rule::*;
        PrattParser::new()
            .op(Op::infix(OR, Assoc::Left))
            .op(Op::infix(AND, Assoc::Left))
            .op(Op::infix(COMPARISON_OP, Assoc::Left)) // all comparison ops grouped
            .op(Op::infix(ADD, Assoc::Left) | Op::infix(SUB, Assoc::Left))
            .op(Op::infix(MUL, Assoc::Left) | Op::infix(DIV, Assoc::Left))
            .op(Op::prefix(NOT))
    };
}

pub fn parse_scl(path: &Path) -> Result<Program, String> {
    let src = fs::read_to_string(path).map_err(|e| format!("read error: {e}"))?;
    parse_scl_from_str(&src)
}

pub fn parse_scl_from_str(src: &str) -> Result<Program, String> {
    let pairs = SCLParser::parse(Rule::program, src).map_err(|e| e.to_string())?;
    let mut functions = Vec::new();

    for pair in pairs {
        if let Rule::program = pair.as_rule() {
            for decl in pair.into_inner() {
                if matches!(
                    decl.as_rule(),
                    Rule::program_block | Rule::function_block | Rule::function | Rule::organization_block
                ) {
                    functions.push(build_function(decl));
                }
            }
        }
    }

    Ok(Program { functions })
}

fn build_function(pair: Pair<Rule>) -> Function {
    let line = pair.as_span().start_pos().line_col().0;
    let kind = match pair.as_rule() {
        Rule::program_block => FunctionKind::Program,
        Rule::function_block => FunctionKind::FB,
        Rule::function => FunctionKind::FC,
        Rule::organization_block => FunctionKind::OB,
        _ => unreachable!(),
    };

    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let statements = inner.next().map(build_statements).unwrap_or_default();

    Function {
        name,
        kind,
        statements,
        line,
    }
}

fn build_statements(pair: Pair<Rule>) -> Vec<Statement> {
    pair.into_inner().map(build_statement).collect()
}

fn build_statement(pair: Pair<Rule>) -> Statement {
    let line = pair.as_span().start_pos().line_col().0;
    let inner_pair = pair.into_inner().next().unwrap();
    match inner_pair.as_rule() {
        Rule::assignment_statement => {
            let mut inner = inner_pair.into_inner();
            let target = parse_expr(inner.next().unwrap().into_inner());
            let value = parse_expr(inner.next().unwrap().into_inner());
            Statement::Assign { target, value, line }
        }
        Rule::if_statement => {
            let mut inner = inner_pair.into_inner();
            let condition = parse_expr(inner.next().unwrap().into_inner());
            let then_branch = build_statements(inner.next().unwrap());
            let mut else_branch = Vec::new();

            while let Some(next) = inner.next() {
                match next.as_rule() {
                    Rule::ELSIF => {
                        let elseif_line = next.as_span().start_pos().line_col().0;
                        let mut elseif_inner = next.into_inner();
                        let elseif_cond =
                            parse_expr(elseif_inner.next().unwrap().into_inner());
                        let elseif_then =
                            build_statements(elseif_inner.next().unwrap());
                        let new_if = Statement::IfStmt {
                            condition: elseif_cond,
                            then_branch: elseif_then,
                            else_branch: vec![],
                            line: elseif_line,
                        };
                        else_branch.push(new_if);
                    }
                    Rule::ELSE => {
                        else_branch =
                            build_statements(next.into_inner().next().unwrap())
                    }
                    _ => {}
                }
            }
            Statement::IfStmt {
                condition,
                then_branch,
                else_branch,
                line,
            }
        }
        Rule::case_statement => {
            let mut inner = inner_pair.into_inner();
            let expression =
                Box::new(parse_expr(inner.next().unwrap().into_inner()));
            let mut cases = Vec::new();
            let mut else_branch = Vec::new();

            for case_pair in inner {
                match case_pair.as_rule() {
                    Rule::case_option => {
                        let mut case_inner = case_pair.into_inner();
                        let labels_pair = case_inner.next().unwrap();
                        let labels = labels_pair
                            .into_inner()
                            .map(|p| parse_expr(p.into_inner()))
                            .collect();
                        let body = build_statements(case_inner.next().unwrap());
                        cases.push((labels, body));
                    }
                    Rule::ELSE => {
                        else_branch = build_statements(
                            case_pair.into_inner().next().unwrap(),
                        )
                    }
                    _ => {}
                }
            }
            Statement::CaseStmt {
                expression,
                cases,
                else_branch,
                line,
            }
        }
        Rule::call_statement => {
            let call_expr = parse_expr(inner_pair.into_inner());
            if let Expression::FuncCall { name, args, line } = call_expr {
                let mapped_args =
                    args.into_iter().map(|arg| ("".to_string(), arg)).collect();
                Statement::Call {
                    name,
                    args: mapped_args,
                    line,
                }
            } else {
                unreachable!(
                    "call_statement did not contain a FuncCall expression"
                )
            }
        }
        _ => unreachable!(
            "Unexpected statement rule: {:?}, content: '{}'",
            inner_pair.as_rule(),
            inner_pair.as_str()
        ),
    }
}

fn build_args(pair: Pair<Rule>) -> Vec<Expression> {
    pair.into_inner()
        .map(|arg_pair| {
            let inner = arg_pair.into_inner().next().unwrap();
            parse_expr(inner.into_inner())
        })
        .collect()
}

fn parse_expr(pairs: Pairs<Rule>) -> Expression {
    PRATT_PARSER
        .map_primary(|primary| {
            let line = primary.as_span().start_pos().line_col().0;
            match primary.as_rule() {
                Rule::number => {
                    Expression::NumberLiteral(primary.as_str().parse().unwrap(), line)
                }
                Rule::boolean => {
                    Expression::BoolLiteral(primary.as_str().eq_ignore_ascii_case("TRUE"), line)
                }
                Rule::identifier => {
                    Expression::Identifier(primary.as_str().to_string())
                }
                Rule::memory_identifier => {
                    Expression::Identifier(primary.as_str().to_string())
                }
                Rule::string => {
                    let raw = primary.as_str();
                    let inner = &raw[1..raw.len() - 1];
                    Expression::StringLiteral(inner.to_string(), line)
                }
                Rule::array_access => {
                    let mut inner = primary.into_inner();
                    let base = Box::new(Expression::Identifier(
                        inner.next().unwrap().as_str().to_string(),
                    ));
                    let index =
                        Box::new(parse_expr(inner.next().unwrap().into_inner()));
                    Expression::Index { base, index, line }
                }
                Rule::function_call => {
                    let mut inner = primary.into_inner();
                    let name = inner.next().unwrap().as_str().to_string();
                    let args = inner.next().map(build_args).unwrap_or_default();
                    Expression::FuncCall { name, args, line }
                }
                Rule::named_arg => {
                    let mut inner = primary.into_inner();
                    let target = parse_expr(inner.next().unwrap().into_inner());
                    let value = parse_expr(inner.next().unwrap().into_inner());
                    Expression::BinaryOp {
                        op: BinOp::Assign,
                        left: Box::new(target),
                        right: Box::new(value),
                        line,
                    }
                }
                Rule::expression => parse_expr(primary.into_inner()),
                _ => unreachable!(
                    "Unexpected primary rule: {:?} at line {}",
                    primary.as_rule(),
                    line
                ),
            }
        })
        .map_prefix(|op, rhs| {
            let line = op.as_span().start_pos().line_col().0;
            let op_type = match op.as_rule() {
                Rule::NOT => UnaryOp::Not,
                _ => unreachable!(),
            };
            Expression::UnaryOp {
                op: op_type,
                expr: Box::new(rhs),
                line,
            }
        })
        .map_infix(|lhs, op, rhs| {
            let line = op.as_span().start_pos().line_col().0;
            let op_type = match op.as_rule() {
                Rule::ADD => BinOp::Add,
                Rule::SUB => BinOp::Sub,
                Rule::MUL => BinOp::Mul,
                Rule::DIV => BinOp::Div,
                Rule::COMPARISON_OP => match op.as_str() {
                    "<>" => BinOp::Neq,
                    "<=" => BinOp::Le,
                    ">=" => BinOp::Ge,
                    "=" => BinOp::Eq,
                    "<" => BinOp::Lt,
                    ">" => BinOp::Gt,
                    _ => unreachable!("Unknown comparison operator {}", op.as_str()),
                },
                Rule::AND => BinOp::And,
                Rule::OR => BinOp::Or,
                _ => unreachable!(),
            };
            Expression::BinaryOp {
                op: op_type,
                left: Box::new(lhs),
                right: Box::new(rhs),
                line,
            }
        })
        .parse(pairs)
}
