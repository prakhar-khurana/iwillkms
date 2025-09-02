//! PLCOpen XML parser (LD/FBD oriented). We extract light-weight AST:
//! POUs become functions; <block> -> calls; simple <variable name=...>
//! with <value> -> assignment.

use std::fs;
use std::path::Path;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::ast::{Expression, Function, FunctionKind, Program, Statement};

/// Parses a PLCOpen XML file from a given path.
/// This is a wrapper for the command-line tool.
pub fn parse_plcopen(path: &Path) -> Result<Program, String> {
    let xml_content = fs::read_to_string(path).map_err(|e| format!("read error: {e}"))?;
    parse_plcopen_from_str(&xml_content)
}

/// Parses a PLCOpen XML string into a Program.
/// This is the core parser used by both the CLI and the Wasm module.
pub fn parse_plcopen_from_str(src: &str) -> Result<Program, String> {
    let mut reader = Reader::from_str(src);
    reader.config_mut().trim_text(true);
    reader.config_mut().expand_empty_elements = false;
    let mut buf = Vec::new();
    let mut program = Program { functions: vec![] };
    let mut current_func: Option<Function> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                if e.name().as_ref().eq_ignore_ascii_case(b"pou") {
                    let mut fname = String::from("Unnamed");
                    let mut kind = FunctionKind::FC;
                    for a in e.attributes().flatten() {
                        if a.key.as_ref().eq_ignore_ascii_case(b"name") {
                            fname = a.unescape_value()
                                .map(|v| v.to_string())
                                .unwrap_or_else(|_| "Unnamed".into());
                        } else if a.key.as_ref().eq_ignore_ascii_case(b"pouType") {
                            let val = a.unescape_value().unwrap_or_default();
                            let v = val.to_ascii_lowercase();
                            if v.contains("functionblock") {
                                kind = FunctionKind::FB;
                            } else if v.contains("program") {
                                if fname.to_uppercase().contains("OB100") {
                                    kind = FunctionKind::OB100;
                                } else if fname.to_uppercase().contains("OB1") {
                                    kind = FunctionKind::OB1;
                                } else if fname.to_uppercase().contains("OB86") {
                                    kind = FunctionKind::OB86;
                                } else if fname.to_uppercase().contains("OB82") {
                                    kind = FunctionKind::OB82;
                                } else if fname.to_uppercase().contains("OB121") {
                                    kind = FunctionKind::OB121;
                                } else {
                                    kind = FunctionKind::OB;
                                }
                            } else {
                                kind = FunctionKind::FC;
                            }
                        }
                    }
                    current_func = Some(Function {
                        name: fname,
                        kind,
                        statements: vec![],
                        line: 0, // Line numbers are less precise in XML
                    });
                } else if e.name().as_ref().eq_ignore_ascii_case(b"block") {
                    if let Some(f) = current_func.as_mut() {
                        let mut call_name = "Block".to_string();
                        for a in e.attributes().flatten() {
                            if a.key.as_ref().eq_ignore_ascii_case(b"name") {
                                call_name = a.unescape_value()
                                    .map(|v| v.to_string())
                                    .unwrap_or_else(|_| "Block".into());
                            }
                        }
                        f.statements.push(Statement::Call {
                            name: call_name,
                            args: vec![],
                            line: 0,
                        });
                    }
                } else if e.name().as_ref().eq_ignore_ascii_case(b"variable") {
                    if let Some((var, val)) = read_variable_assignment(&mut reader, e)? {
                        if let Some(f) = current_func.as_mut() {
                            f.statements.push(Statement::Assign {
                                target: Expression::Identifier(var),
                                value: val,
                                line: 0,
                            });
                        }
                    }
                }
            }
            Ok(Event::End(e)) => {
                if e.name().as_ref().eq_ignore_ascii_case(b"pou") {
                    if let Some(f) = current_func.take() {
                        program.functions.push(f);
                    }
                }
            }
             Err(e) => {
                return Err(format!("XML parse error at position {}: {}", reader.buffer_position(), e));
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(program)
}

fn read_variable_assignment(
    reader: &mut Reader<&[u8]>,
    start: quick_xml::events::BytesStart<'_>,
) -> Result<Option<(String, Expression)>, String> {
    let mut var_name = None::<String>;
    for a in start.attributes().flatten() {
        if a.key.as_ref().eq_ignore_ascii_case(b"name") {
            var_name = Some(a.unescape_value()
                .map(|v| v.to_string())
                .unwrap_or_else(|_| "Var".into()));
        }
    }
    let mut buf = Vec::new();
    let mut value_text = None::<String>;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if e.name().as_ref().eq_ignore_ascii_case(b"value") => {
                value_text = read_element_text(reader)?;
            }
            Ok(Event::End(_)) => {
                // This end tag could be for <value> or <variable>
                // We break after finding a value to handle nested structures correctly.
                if value_text.is_some() {
                    break;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    if let (Some(name), Some(val)) = (var_name, value_text) {
        let expr = match val.to_ascii_uppercase().as_str() {
            "TRUE" => Expression::BoolLiteral(true, 0),
            "FALSE" => Expression::BoolLiteral(false, 0),
            _ => {
                if let Ok(n) = val.parse::<i64>() {
                    Expression::NumberLiteral(n, 0)
                } else {
                    Expression::Identifier(val)
                }
            }
        };
        Ok(Some((name, expr)))
    } else {
        Ok(None)
    }
}

fn read_element_text(reader: &mut Reader<&[u8]>) -> Result<Option<String>, String> {
    let mut buf = Vec::new();
    let mut out = String::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Text(t)) => {
                out.push_str(&t.unescape().map_err(|e| e.to_string())?);
            }
            Ok(Event::End(_)) => {
                break;
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}