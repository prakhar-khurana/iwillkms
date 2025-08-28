//! Simplified parser for Siemens Structured Text (SCL).
//! Extracts enough structure for rule checks: functions/blocks, assigns,
//! IF/ELSE, calls, and basic expressions (division, literals, indexing).

use std::fs;
use std::path::Path;


use pest_derive::Parser;

use crate::ast::{
    BinOp, Expression, Function, FunctionKind, Program, Statement, UnaryOp, Variable,
};

#[derive(Parser)]
#[grammar_inline = r#"
WHITESPACE = _{ " " | "\t" | "\r" | "\n" }
ident = @{ (ASCII_ALPHANUMERIC | "_" | ".")+ }
number = @{ ASCII_DIGIT+ }
operator = _{ "=" | ":=" | "+" | "-" | "*" | "/" | "<" | "<=" | ">" | ">=" }

stmt_end = _{ ";" }
"#]
#[allow(dead_code)]
struct SclMiniParser;

pub fn parse_scl(path: &Path) -> Result<Program, String> {
    let src = fs::read_to_string(path).map_err(|e| format!("read error: {e}"))?;
    parse_scl_from_str(&src)
}

pub fn parse(path: &Path) -> Result<Program, String> {
    parse_scl(path)
}

pub fn parse_scl_from_str(src: &str) -> Result<Program, String> {
    let mut program = Program { functions: vec![] };

    let mut current_func: Option<Function> = None;
    let mut if_stack: Vec<Vec<Statement>> = Vec::new();

    let mut line_no = 0usize;
    let lines: Vec<&str> = src.lines().collect();

    while line_no < lines.len() {
        let raw = lines[line_no];
        line_no += 1;

        let line = raw.trim();
        if line.is_empty() {
            continue;
        }

        // NEW: Check for and preserve full-line comments
        if line.starts_with("(*") && line.ends_with("*)") {
            let text = line.to_string();
            push_stmt(current_func.as_mut(), Statement::Comment { text, line: line_no });
            continue;
        }
        
        // The rest of the parsing loop uses a line with comments removed
        // Use strip_inline_comment so both // and (* *) inline comments are removed
        let line_clean = strip_inline_comment(raw);
        let line = line_clean.trim();


        // Block starts
        if starts_with_keyword(&line, "FUNCTION_BLOCK")
            || starts_with_keyword(&line, "FUNCTION")
            || starts_with_keyword(&line, "ORGANIZATION_BLOCK")
            || starts_with_keyword(&line, "PROGRAM")
        {
             if let Some(mut f) = current_func.take() {
                // This also correctly handles any unclosed IF statements from the previous block.
                while let Some(mut body) = if_stack.pop() {
                    f.statements.append(&mut body);
                }
                program.functions.push(f);
            }
            let name = grab_second_token(&line).unwrap_or_else(|| "Unnamed".to_string());
            let kind = if starts_with_keyword(&line, "FUNCTION_BLOCK") {
                FunctionKind::FB
            } else if starts_with_keyword(&line, "FUNCTION") {
                FunctionKind::FC
            } else if starts_with_keyword(&line, "PROGRAM") {
                FunctionKind::Program
            }
            else {
                let up = name.to_ascii_uppercase();
    			let ob_num = up.strip_prefix("OB").and_then(|s| s.parse::<u32>().ok());
    			match ob_num {
        			Some(121) => FunctionKind::OB121,
        			Some(100) => FunctionKind::OB100,
        			Some(86)  => FunctionKind::OB86,
        			Some(82)  => FunctionKind::OB82,
        			Some(1)   => FunctionKind::OB1,
        			Some(_)   => FunctionKind::OB, // other OBs
        			None      => FunctionKind::OB,
    			}
            };
            current_func = Some(Function {
                name,
                kind,
                statements: vec![],
                line: line_no,
            });
            continue;
        }

        // Block ends
        if starts_with_keyword(&line, "END_FUNCTION_BLOCK")
            || starts_with_keyword(&line, "END_FUNCTION")
            || starts_with_keyword(&line, "END_ORGANIZATION_BLOCK")
            || starts_with_keyword(&line, "END_PROGRAM")
        {
            if let Some(mut f) = current_func.take() {
                while let Some(mut body) = if_stack.pop() {
                    f.statements.append(&mut body);
                }
                program.functions.push(f);
            }
            continue;
        }

        // IF ... THEN (supports multi-line conditions). Build the condition text
        // up to the THEN keyword, then parse it with parse_expr.
        if starts_with_keyword(&line, "IF ") || line.to_uppercase().starts_with("IF(") || line.to_uppercase().starts_with("IF (") {
            let mut cond_text = String::new();
            let chunk = line;
            // accumulate until THEN appears
            while !chunk.to_ascii_uppercase().contains("THEN") && line_no < lines.len() {
                cond_text.push_str(" ");
                cond_text.push_str(&chunk);
                let nxt_raw = lines[line_no];
                line_no += 1;
                let own_string = strip_inline_comment(nxt_raw);
                let chunk = own_string.trim();
                if chunk.is_empty() { break; }
            }
            // handle final chunk containing THEN
            if chunk.to_ascii_uppercase().contains("THEN") {
                let up = chunk.to_ascii_uppercase();
                if let Some(ti) = up.find("THEN") {
                    cond_text.push(' ');
                    cond_text.push_str(&chunk[..ti]);
                }
            }
            let cond_expr = parse_expr(&cond_text.trim(), line_no);
            if_stack.push(vec![Statement::IfStmt {
                condition: cond_expr,
                then_branch: vec![],
                else_branch: vec![],
                line: line_no,
            }]);
            continue;
        }

        // ELSE
        if line.to_uppercase().starts_with("ELSE") {
            if let Some(body) = if_stack.last_mut() {
                body.push(Statement::ElseMarker { line: line_no });
            }
            continue;
        }

        // END_IF
        if line.to_uppercase().starts_with("END_IF") {
            if let Some(body) = if_stack.pop() {
                if let Some(Statement::IfStmt {
                    condition,
                    line,
                    ..
                }) = body.get(0).cloned()
                {
                    let mut then_branch = vec![];
                    let mut else_branch = vec![];
                    let mut in_else = false;
                    for st in body.into_iter().skip(1) {
                        match st {
                            Statement::ElseMarker { .. } => in_else = true,
                            other => {
                                if in_else {
                                    else_branch.push(other);
                                } else {
                                    then_branch.push(other);
                                }
                            }
                        }
                    }
                    let final_if = Statement::IfStmt {
                        condition,
                        then_branch,
                        else_branch,
                        line,
                    };
                    push_stmt(current_func.as_mut(), final_if);
                }
            }
            continue;
        }
        // CASE ... OF ... (supports multi-line cases). This is a simplified
        if starts_with_keyword(&line, "CASE ") {
            let case_expr_text = &line[4..].trim().trim_end_matches("OF").trim();
            let case_expr = parse_expr(case_expr_text, line_no);
            
            let mut all_cases: Vec<(Vec<Expression>, Vec<Statement>)> = vec![];
            let mut else_branch: Vec<Statement> = vec![];
            let mut current_statements: Vec<Statement> = vec![];
            let mut in_else_block = false;

            // Consume the body of the CASE statement
            while line_no < lines.len() {
                let body_raw = lines[line_no];
                line_no += 1;
                let body_line_string = strip_inline_comment(body_raw);
                let body_line = body_line_string.trim();

                if starts_with_keyword(body_line, "END_CASE") {
                    if !current_statements.is_empty() {
                        if in_else_block {
                            else_branch.append(&mut current_statements);
                        } else if let Some(last_case) = all_cases.last_mut() {
                            last_case.1.append(&mut current_statements);
                        }
                    }
                    break;
                }

                if starts_with_keyword(body_line, "ELSE") {
                    if let Some(last_case) = all_cases.last_mut() {
                        last_case.1.append(&mut current_statements);
                        current_statements.clear();
                    }
                    in_else_block = true;
                    continue;
                }
                
                // Check if the line is a case label (e.g., "1, 2:")
                if body_line.contains(':') {
                    if let Some(last_case) = all_cases.last_mut() {
                       last_case.1.append(&mut current_statements);
                       current_statements.clear();
                    }
                    if let Some((labels_str, _)) = split_once(body_line, ":") {
                        let labels = labels_str.split(',')
                        .map(|s| parse_expr(s.trim(), line_no))
                        .collect::<Vec<_>>();
                    all_cases.push((labels, vec![]));
                } }else if !body_line.is_empty() {
                    // Statement within the current case: support assignments and calls
                    if body_line.contains(":=") {
                        let (lhs, rhs) = split_once(&body_line, ":=").unwrap_or((body_line, ""));
                        current_statements.push(Statement::Assign {
                            target: Variable { name: lhs.trim().to_string() },
                            value: parse_expr(rhs.trim_end_matches(';'), line_no),
                            line: line_no,
                        });
                    } else if looks_like_call(body_line) {
                        let (name, args_str) = split_once(&body_line, "(").unwrap_or((body_line, ""));
                        let name = name.trim().to_string();
                        let args = parse_call_args(args_str, line_no);
                        current_statements.push(Statement::Call { name, args, line: line_no });
                    }
                }
            }

            push_stmt(current_func.as_mut(), Statement::CaseStmt {
                expression: Box::new(case_expr),
                cases: all_cases,
                else_branch,
                line: line_no,
            });
            continue;
        }

        // Assignment: X := Y;
        if line.contains(":=") && line.trim_end().ends_with(';') {
            let (lhs, rhs) = split_once(&line, ":=").unwrap_or((line ,""));
            let lhs = lhs.trim().trim_end_matches(';').to_string();
            let rhs = rhs.trim().trim_end_matches(';').to_string();
            let expr = parse_expr(&rhs, line_no);
            push_stmt(
                current_func.as_mut(),
                Statement::Assign {
                    target: Variable { name: lhs },
                    value: expr,
                    line: line_no,
                },
            );
            continue;
        }

        // Function/FB call
        if looks_like_call(&line) {
            let (name, args_str) = split_once(&line, "(").unwrap_or((line, ""));
            let name = name.trim().to_string();
            let args = parse_call_args(args_str, line_no); // Use the new helper
            push_stmt(
                current_func.as_mut(),
                Statement::Call {
                    name,
                    args, // Pass the parsed arguments
                    line: line_no,
                },
            );
            continue;
        }

        // Fallback: capture an indexing expression if present
        if let Some(idx_expr) = extract_index_expr(&line, line_no) {
            push_stmt(current_func.as_mut(), Statement::Expr {
                expr: idx_expr,
                line: line_no,
            });
        }
    }

    if let Some(mut f) = current_func.take() {
        while let Some(mut body) = if_stack.pop() {
            f.statements.append(&mut body);
        }
        program.functions.push(f);
    }

    Ok(program)
}

fn push_stmt(current_func: Option<&mut Function>, stmt: Statement) {
    if let Some(f) = current_func {
        f.statements.push(stmt);
    }
}

fn starts_with_keyword(s: &str, kw: &str) -> bool {
    s.trim_start().to_uppercase().starts_with(&kw.to_uppercase())
}

fn grab_second_token(s: &str) -> Option<String> {
    let toks: Vec<&str> = s.split_whitespace().collect();
    toks.get(1).map(|t| t.trim_matches(':').to_string())
}

fn split_once<'a>(s: &'a str, pat: &str) -> Option<(&'a str, &'a str)> {
    let mut it = s.splitn(2, pat);
    Some((it.next()?, it.next()?))
}

fn strip_inline_comment(line: &str) -> String {
    let mut s = line.to_string();
    if let Some(i) = s.find("//") {
        s.truncate(i);
    }
    if let (Some(a), Some(b)) = (s.find("(*"), s.find("*)")) {
        if a < b && b+2 <= s.len() {
            let mut t = String::new();
            t.push_str(&s[..a]);
            if b + 2 < s.len() {  // Check bounds before slicing
                t.push_str(&s[b + 2..]);
            }
            s = t;
        }
    }
    s
}

fn looks_like_call(line: &str) -> bool {
    let cleaned = strip_inline_comment(line);
    let t = cleaned.trim();
    // Accept calls that end with ");" possibly followed by whitespace
    t.contains('(') && t.ends_with(");")
}

/// Extract an indexing expression from a raw line if present, otherwise return None.
/// The index expression is parsed via `parse_expr` to support expressions inside
/// brackets (e.g. arr[i+1]).
fn extract_index_expr(line: &str, line_no: usize) -> Option<Expression> {
    let txt = line.trim();
    if let Some(lb) = txt.find('[') {
        if let Some(rb_rel) = txt[lb..].find(']') {
            let rb = lb + rb_rel;
            let base = txt[..lb].trim();
            let idx = txt[lb + 1..rb].trim();
            return Some(Expression::Index {
                base: Box::new(Expression::VariableRef(base.to_string())),
                index: Box::new(parse_expr(idx, line_no)),
                line: line_no,
            });
        }
    }
    None
}
/// NEW HELPER: Parses the argument string from a function call.
/// e.g., "IN := 1, PT := REAL_TO_TIME(gMainLogic.par.recipe.milk * 10))"
fn parse_call_args(args_str: &str, line_no: usize) -> Vec<(String, Expression)> {
    let mut args = Vec::new();
    // Strip to the matching closing paren for robustness
    let mut cleaned = args_str.trim();
    if let Some(rp) = cleaned.rfind(')') { cleaned = &cleaned[..rp]; }
    if let Some(lp) = cleaned.find('(') { cleaned = &cleaned[lp+1..]; }
    let cleaned_args = cleaned.trim_end_matches(';');

    for part in cleaned_args.split(',') {
        if let Some((name, value_str)) = split_once(part, ":=") {
            let arg_name = name.trim().to_string();
            let arg_value = parse_expr(value_str.trim(), line_no);
            args.push((arg_name, arg_value));
        }
    }
    args
}

/// --- Pratt parser implementation ---
/// Tokenize a tiny subset for expressions. Tokens include identifiers,
/// numbers, boolean literals, parentheses, and operators (+,-,*,/,=, <>, <,
/// <=, >, >=, AND, OR, NOT). Whitespace is ignored. Dots and underscores
/// are allowed inside identifiers.
#[derive(Debug, Clone, PartialEq)]
enum Tok<'a> {
    Ident(&'a str),
    Number(i64),
    True,
    False,
    LParen,
    RParen,
    Assign,
    Comma,
    Op(&'a str), // one of: + - * / = <> < <= > >= AND OR NOT
}

fn tokenize(mut s: &str) -> Vec<Tok<'_>> {
    let mut out = vec![];
    while !s.is_empty() {
        let st = s.trim_start();
        let skipped = s.len() - st.len();
        s = st;
        if s.is_empty() { break; }

        let c = s.as_bytes()[0] as char;
        if c.is_ascii_digit() {
            let len = s.chars().take_while(|c| c.is_ascii_digit()).count();
            let n = s[..len].parse::<i64>().unwrap_or(0);
            out.push(Tok::Number(n));
            s = &s[len..];
            continue;
        }
        if c == '(' { out.push(Tok::LParen); s = &s[1..]; continue; }
        if c == ')' { out.push(Tok::RParen); s = &s[1..]; continue; }

        // 2-char ops first
        if s.starts_with("<>") || s.starts_with("<=") || s.starts_with(">=") {
            out.push(Tok::Op(&s[..2])); s = &s[2..]; continue;
        }
        // 1-char ops
        if "+-*/=<>()".contains(c) {
            out.push(Tok::Op(&s[..1])); s = &s[1..]; continue;
        }
        if c == ',' { out.push(Tok::Comma); s = &s[1..]; continue; }
        // identifiers / keywords
        let len = s
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
            .count();
        if len > 0 {
            let ident = &s[..len];
            let up = ident.to_ascii_uppercase();
            match up.as_str() {
                "TRUE" => out.push(Tok::True),
                "FALSE" => out.push(Tok::False),
                "AND" | "OR" | "NOT" => out.push(Tok::Op(ident)),
                _ => out.push(Tok::Ident(ident)),
            }
            s = &s[len..];
            continue;
        }

        // fallback: skip a char
        s = &s[1..];
        let _ = skipped; // silence unused var
    }
    out
}

/// Return precedence and right-associativity for an operator token.
fn prec(op: &str) -> (u8, bool) {
    match op.to_ascii_uppercase().as_str() {
        "NOT" => (5, true),
        "*" | "/" => (4, false),
        "+" | "-" => (3, false),
        "=" | "<>" | "<" | "<=" | ">" | ">=" => (2, false),
        "AND" => (1, false),
        "OR" => (0, false),
        _ => (0, false),
    }
}

/// Map an operator string to a BinOp. Returns None for unknown ops.
fn bin_of(op: &str) -> Option<BinOp> {
    Some(match op.to_ascii_uppercase().as_str() {
        "+" => BinOp::Add,
        "-" => BinOp::Sub,
        "*" => BinOp::Mul,
        "/" => BinOp::Div,
        "=" => BinOp::Eq,
        "<>" => BinOp::Neq,
        "<" => BinOp::Lt,
        "<=" => BinOp::Le,
        ">" => BinOp::Gt,
        ">=" => BinOp::Ge,
        "AND" => BinOp::And,
        "OR" => BinOp::Or,
        _ => return None,
    })
}


/// Parse a full expression using Pratt parsing. Handles unary NOT,
/// arithmetic, comparisons, boolean AND/OR, and parentheses.
fn parse_expr(text: &str, line: usize) -> Expression {
    let toks = tokenize(text);
    let mut i = 0usize;

    fn parse_primary<'a>(
        toks: &Vec<Tok<'a>>,
        i: &mut usize,
        line: usize,
        original_text: &str,
    ) -> Expression {
        if *i >= toks.len() {  // Add bounds check
        return Expression::VariableRef(original_text.trim().to_string());
        }
        match toks.get(*i) {
            Some(Tok::Number(n)) => {
                *i += 1;
                Expression::NumberLiteral(*n, line)
            }
            Some(Tok::True) => {
                *i += 1;
                Expression::BoolLiteral(true, line)
            }
            Some(Tok::False) => {
                *i += 1;
                Expression::BoolLiteral(false, line)
            }
            Some(Tok::Ident(id)) => {
                *i += 1;
                // Check for a function call
                if let Some(Tok::LParen) = toks.get(*i) {
                    *i += 1; // Consume '('
                    let mut args = Vec::new();
                    // Parse arguments until ')'
                    if !matches!(toks.get(*i), Some(Tok::RParen)) {
                        loop {
                            args.push(parse_bp(toks, i, 0, line, original_text));
                            if matches!(toks.get(*i), Some(Tok::RParen)) {
                                break;
                            }
                            if matches!(toks.get(*i), Some(Tok::Comma)) {
                                *i += 1; // Consume ','
                            } else {
                                break; // Unexpected token
                            }
                        }
                    }
                    if matches!(toks.get(*i), Some(Tok::RParen)) {
                        *i += 1; // Consume ')'
                    }
                    Expression::FuncCall { name: (*id).to_string(), args, line }
                } else {
                    Expression::VariableRef((*id).to_string())
                }
            }
            Some(Tok::LParen) => {
                *i += 1;
                let e = parse_bp(toks, i, 0, line, original_text);
                if matches!(toks.get(*i), Some(Tok::RParen)) {
                    *i += 1;
                }
                e
            }
            _ => {
                // Fallback: produce something stable without capturing env
                Expression::VariableRef(original_text.trim().to_string())
            }
        }
    }

    fn parse_bp<'a>(
        toks: &Vec<Tok<'a>>,
        i: &mut usize,
        min_bp: u8,
        line: usize,
        original_text: &str,
    ) -> Expression {
        let mut lhs = match toks.get(*i) {
            Some(Tok::Op(op)) if op.to_ascii_uppercase() == "NOT" => {
                *i += 1;
                let (r_bp, _) = prec("NOT");
                let rhs = parse_bp(toks, i, r_bp, line, original_text);
                Expression::UnaryOp {
                    op: UnaryOp::Not,
                    expr: Box::new(rhs),
                    line,
                }
            }
            _ => parse_primary(toks, i, line, original_text),
        };

        loop {
            let op = match toks.get(*i) {
                Some(Tok::Op(op)) => *op,
                _ => break,
            };
            if op == ")" {
                break;
            }
            let (lbp, right_assoc) = prec(op);
            if lbp < min_bp {
                break;
            }

            *i += 1;
            let rbp = if right_assoc { lbp } else { lbp + 1 };
            let rhs = parse_bp(toks, i, rbp, line, original_text);
            if let Some(b) = bin_of(op) {
                lhs = Expression::BinaryOp {
                    op: b,
                    left: Box::new(lhs),
                    right: Box::new(rhs),
                    line,
                };
            } else {
                break;
            }
        }
        lhs
    }

    parse_bp(&toks, &mut i, 0, line, text)
}