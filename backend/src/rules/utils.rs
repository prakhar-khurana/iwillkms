//! Shared utility functions for rule implementations.

use crate::ast::{BinOp, Expression, UnaryOp};

/// Helper to get a text representation of an expression.
pub fn expr_text(e: &Expression) -> String {
    match e {
        Expression::NumberLiteral(n, _) => n.to_string(),
        Expression::BoolLiteral(b, _) => b.to_string(),
        Expression::VariableRef(v) => v.clone(),
        Expression::Index { base, index, .. } => format!("{}[{}]", expr_text(base), expr_text(index)),
        Expression::UnaryOp { op, expr, .. } => match op {
            UnaryOp::Not => format!("NOT {}", expr_text(expr)),
        },
        Expression::BinaryOp { op, left, right, .. } => {
            let o = match op {
                BinOp::Add => "+",
                BinOp::Sub => "-",
                BinOp::Mul => "*",
                BinOp::Div => "/",
                BinOp::Eq => "=",
                BinOp::Neq => "<>",
                BinOp::Lt => "<",
                BinOp::Le => "<=",
                BinOp::Gt => ">",
                BinOp::Ge => ">=",
                BinOp::And => "AND",
                BinOp::Or => "OR",
            };
            format!("({} {} {})", expr_text(left), o, expr_text(right))
        }
        Expression::FuncCall { name, args, .. } => {
            let arg_str = args.iter().map(expr_text).collect::<Vec<_>>().join(", ");
            format!("{}({})", name, arg_str)
        }
    }
}