//! Small expression language for declarative rule `where` / `on` / `having` clauses.
//!
//! Supports comparisons, `AND`/`OR`/`NOT`, `IS NULL`, `IS NOT NULL`, and `IN (...)`.
//! Field references use `alias.field`, `alias.attr:name`, `subject`, or `attr:name`.

use std::collections::BTreeMap;

use intermed_doctor_core::facts::Fact;

/// Evaluation context: alias → fact, settings literals, and optional computed
/// variables (aggregate `count`, `writer_count`, …) so a `having` clause can
/// reference the aggregate it is gating, not just bound facts.
pub struct ExprCtx<'a> {
    pub bindings: &'a BTreeMap<String, &'a Fact>,
    pub settings: &'a BTreeMap<String, String>,
    #[allow(clippy::struct_field_names)]
    pub vars: Option<&'a BTreeMap<String, String>>,
}

/// Extract equality join keys (`left = right`) from an `on` / `match_on` expression.
///
/// Only comparisons between two identifiers are returned; literal comparisons and
/// non-equality operators are ignored. Used by the in-process interpreter to
/// build hash indexes instead of nested loops.
#[must_use]
pub fn extract_equijoin_keys(expr: &str) -> Vec<(String, String)> {
    match parse_expr(expr.trim()) {
        Ok(ast) => collect_equijoins(&ast),
        Err(_) => Vec::new(),
    }
}

fn collect_equijoins(expr: &Expr) -> Vec<(String, String)> {
    match expr {
        Expr::Cmp(left, CmpOp::Eq, right) => {
            if let (Some(l), Some(r)) = (expr_ident(left), expr_ident(right)) {
                vec![(l, r)]
            } else {
                Vec::new()
            }
        }
        Expr::And(a, b) => {
            let mut out = collect_equijoins(a);
            out.extend(collect_equijoins(b));
            out
        }
        Expr::Or(a, b) => {
            let mut out = collect_equijoins(a);
            out.extend(collect_equijoins(b));
            out
        }
        Expr::Not(_) => Vec::new(),
        _ => Vec::new(),
    }
}

fn expr_ident(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Ident(id) => Some(id.clone()),
        _ => None,
    }
}

/// Evaluate `expr` against `ctx`. Returns false on parse/type errors.
pub fn eval_bool(expr: &str, ctx: &ExprCtx<'_>) -> bool {
    match parse_expr(expr.trim()) {
        Ok(ast) => eval_ast(&ast, ctx).unwrap_or(false),
        Err(_) => false,
    }
}

/// Resolve a term like `m.loader`, `attr:file`, or `subject` from bindings.
pub fn resolve_term(term: &str, ctx: &ExprCtx<'_>) -> Option<String> {
    // Computed aggregate vars (`count`, `writer_count`, …) are bare identifiers.
    if !term.contains('.') && !term.contains(':') {
        if let Some(v) = ctx.vars.and_then(|vars| vars.get(term)) {
            return Some(v.clone());
        }
    }
    if term == "subject" {
        return ctx.bindings.values().next().map(|f| f.subject.clone());
    }
    if let Some(attr) = term.strip_prefix("attr:") {
        return ctx
            .bindings
            .values()
            .find_map(|fact| term_value(fact, attr));
    }
    if let Some((alias, rest)) = term.split_once('.') {
        let fact = ctx.bindings.get(alias)?;
        if let Some(attr) = rest.strip_prefix("attr:") {
            return term_value(fact, attr);
        }
        if rest == "subject" {
            return Some(fact.subject.clone());
        }
        if rest == "kind" {
            return Some(fact.kind.clone());
        }
        return term_value(fact, rest);
    }
    None
}

/// Resolve a term from a single fact (v1 `where_all` compatibility).
pub fn term_value(fact: &Fact, term: &str) -> Option<String> {
    if term == "subject" {
        return Some(fact.subject.clone());
    }
    if term == "kind" {
        return Some(fact.kind.clone());
    }
    let key = term.strip_prefix("attr:").unwrap_or(term);
    if let Some(value) = fact.attributes.get(key) {
        return Some(attr_value_string(value));
    }
    // Bytecode-derived facts sometimes store values under alternate keys; try
    // common aliases so correlation rules do not silently miss matches.
    term_value_alias(fact, key)
}

/// Fallback attribute lookup for non-standard collector attribute names.
fn term_value_alias(fact: &Fact, key: &str) -> Option<String> {
    const ALIASES: &[(&str, &[&str])] = &[
        ("archive", &["file", "jar", "locator"]),
        ("path", &["subject", "resource", "file"]),
        ("trust_score", &["score"]),
        ("mod_id", &["id", "name"]),
    ];
    for (canonical, alts) in ALIASES {
        if key == *canonical {
            for alt in *alts {
                if let Some(value) = fact.attributes.get(*alt) {
                    return Some(attr_value_string(value));
                }
            }
        }
    }
    None
}

fn attr_value_string(value: &intermed_doctor_core::facts::AttrValue) -> String {
    match value {
        intermed_doctor_core::facts::AttrValue::Str(s) => s.clone(),
        intermed_doctor_core::facts::AttrValue::Int(i) => i.to_string(),
        intermed_doctor_core::facts::AttrValue::Float(f) => f.to_string(),
        intermed_doctor_core::facts::AttrValue::Bool(b) => b.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Expr {
    Literal(String),
    Ident(String),
    IsNull(Box<Expr>),
    IsNotNull(Box<Expr>),
    In(Box<Expr>, Vec<String>),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Cmp(Box<Expr>, CmpOp, Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug)]
enum ParseError {
    Empty,
    Unexpected(&'static str),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Empty => f.write_str("empty expression"),
            ParseError::Unexpected(what) => write!(f, "unexpected {what}"),
        }
    }
}

/// Parse-check a boolean expression without evaluating it.
///
/// Used by rule-pack validation so that a malformed `on` / `where` / `having` /
/// `match_on` clause is rejected at load time with a diagnostic, instead of
/// silently evaluating to `false` for every row at runtime (see [`eval_bool`]).
///
/// # Errors
/// Returns a human-readable description of the first parse failure.
pub fn check_expr(expr: &str) -> Result<(), String> {
    parse_expr(expr.trim()).map(|_| ()).map_err(|e| e.to_string())
}

/// Alias prefixes referenced in `alias.field` identifiers within an expression
/// (e.g. `m.loader = 'fabric' AND e.loader != m.loader` → `{m, e}`). Bare
/// identifiers (`count`, `subject`, `TRUE`) and `attr:`/literal terms have no
/// alias and are skipped. Used by rule-pack validation to catch a misspelled
/// alias that would otherwise make the rule silently never match.
#[must_use]
pub fn referenced_aliases(expr: &str) -> Vec<String> {
    let Ok(ast) = parse_expr(expr.trim()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_aliases(&ast, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_aliases(expr: &Expr, out: &mut Vec<String>) {
    match expr {
        Expr::Ident(id) => {
            if let Some((alias, _)) = id.split_once('.') {
                // Only a plain identifier alias counts — not `attr:foo` (aliasless),
                // a `{settings.x}` template placeholder, or `settings` itself.
                let is_ident = !alias.is_empty()
                    && alias != "settings"
                    && alias.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                if is_ident {
                    out.push(alias.to_string());
                }
            }
        }
        Expr::IsNull(e) | Expr::IsNotNull(e) | Expr::Not(e) | Expr::In(e, _) => {
            collect_aliases(e, out);
        }
        Expr::And(a, b) | Expr::Or(a, b) | Expr::Cmp(a, _, b) => {
            collect_aliases(a, out);
            collect_aliases(b, out);
        }
        Expr::Literal(_) => {}
    }
}

fn parse_expr(input: &str) -> Result<Expr, ParseError> {
    let tokens = tokenize(input)?;
    let mut parser = Parser { tokens, pos: 0 };
    let expr = parser.parse_or()?;
    if parser.pos < parser.tokens.len() {
        return Err(ParseError::Unexpected("trailing tokens"));
    }
    Ok(expr)
}

fn tokenize(input: &str) -> Result<Vec<Token>, ParseError> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        match c {
            '\'' => {
                chars.next();
                let mut s = String::new();
                while let Some(ch) = chars.next() {
                    if ch == '\'' {
                        if chars.peek() == Some(&'\'') {
                            chars.next();
                            s.push('\'');
                            continue;
                        }
                        break;
                    }
                    s.push(ch);
                }
                tokens.push(Token::Str(s));
            }
            '(' => {
                chars.next();
                tokens.push(Token::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(Token::RParen);
            }
            ',' => {
                chars.next();
                tokens.push(Token::Comma);
            }
            '=' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                }
                tokens.push(Token::Eq);
            }
            '!' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::Ne);
                } else {
                    tokens.push(Token::Not);
                }
            }
            '<' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::Le);
                } else {
                    tokens.push(Token::Lt);
                }
            }
            '>' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::Ge);
                } else {
                    tokens.push(Token::Gt);
                }
            }
            _ if c.is_ascii_alphabetic() || c == '_' || c == ':' || c == '.' || c == '{' => {
                let mut ident = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' || ch == '.' || ch == '{' || ch == '}' {
                        ident.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                let upper = ident.to_ascii_uppercase();
                match upper.as_str() {
                    "AND" => tokens.push(Token::And),
                    "OR" => tokens.push(Token::Or),
                    "NOT" => tokens.push(Token::Not),
                    "IS" => tokens.push(Token::Is),
                    "IN" => tokens.push(Token::In),
                    "NULL" => tokens.push(Token::Null),
                    "TRUE" => tokens.push(Token::Str("true".into())),
                    "FALSE" => tokens.push(Token::Str("false".into())),
                    _ => tokens.push(Token::Ident(ident)),
                }
            }
            _ if c.is_ascii_digit() => {
                let mut num = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_ascii_digit() || ch == '.' {
                        num.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                tokens.push(Token::Str(num));
            }
            _ => return Err(ParseError::Unexpected("invalid character")),
        }
    }
    if tokens.is_empty() {
        return Err(ParseError::Empty);
    }
    Ok(tokens)
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Str(String),
    LParen,
    RParen,
    Comma,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Not,
    Is,
    In,
    Null,
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn bump(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Token::Or)) {
            self.bump();
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Some(Token::And)) {
            self.bump();
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, ParseError> {
        if matches!(self.peek(), Some(Token::Not)) {
            self.bump();
            let inner = self.parse_not()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_postfix()
    }

    fn parse_postfix(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.parse_primary()?;
        loop {
            if matches!(self.peek(), Some(Token::Is)) {
                self.bump();
                let not = matches!(self.peek(), Some(Token::Not));
                if not {
                    self.bump();
                }
                if !matches!(self.peek(), Some(Token::Null)) {
                    return Err(ParseError::Unexpected("expected NULL after IS"));
                }
                self.bump();
                expr = if not {
                    Expr::IsNotNull(Box::new(expr))
                } else {
                    Expr::IsNull(Box::new(expr))
                };
                continue;
            }
            if matches!(self.peek(), Some(Token::In)) {
                self.bump();
                if !matches!(self.peek(), Some(Token::LParen)) {
                    return Err(ParseError::Unexpected("expected ( after IN"));
                }
                self.bump();
                let mut values = Vec::new();
                loop {
                    match self.bump() {
                        Some(Token::Str(s)) => values.push(s),
                        Some(Token::Ident(s)) => values.push(s),
                        _ => return Err(ParseError::Unexpected("expected literal in IN list")),
                    }
                    match self.peek() {
                        Some(Token::Comma) => {
                            self.bump();
                        }
                        Some(Token::RParen) => {
                            self.bump();
                            break;
                        }
                        _ => return Err(ParseError::Unexpected("expected , or ) in IN list")),
                    }
                }
                expr = Expr::In(Box::new(expr), values);
                continue;
            }
            if let Some(op) = self.peek_cmp_op() {
                self.bump();
                let right = self.parse_postfix()?;
                expr = Expr::Cmp(Box::new(expr), op, Box::new(right));
                continue;
            }
            break;
        }
        Ok(expr)
    }

    fn peek_cmp_op(&self) -> Option<CmpOp> {
        match self.peek() {
            Some(Token::Eq) => Some(CmpOp::Eq),
            Some(Token::Ne) => Some(CmpOp::Ne),
            Some(Token::Lt) => Some(CmpOp::Lt),
            Some(Token::Le) => Some(CmpOp::Le),
            Some(Token::Gt) => Some(CmpOp::Gt),
            Some(Token::Ge) => Some(CmpOp::Ge),
            _ => None,
        }
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        match self.bump() {
            Some(Token::Ident(id)) if id.eq_ignore_ascii_case("TRUE") => {
                Ok(Expr::Literal("true".into()))
            }
            Some(Token::Ident(id)) if id.eq_ignore_ascii_case("FALSE") => {
                Ok(Expr::Literal("false".into()))
            }
            Some(Token::Ident(id)) => Ok(Expr::Ident(id)),
            Some(Token::Str(s)) => Ok(Expr::Literal(s)),
            Some(Token::LParen) => {
                let inner = self.parse_or()?;
                if !matches!(self.peek(), Some(Token::RParen)) {
                    return Err(ParseError::Unexpected("expected )"));
                }
                self.bump();
                Ok(inner)
            }
            _ => Err(ParseError::Unexpected("expected expression")),
        }
    }
}

fn eval_ast(expr: &Expr, ctx: &ExprCtx<'_>) -> Option<bool> {
    match expr {
        Expr::Literal(s) => Some(s == "true"),
        Expr::Ident(id) => resolve_term(id, ctx).map(|v| v == "true"),
        Expr::IsNull(e) => Some(eval_value(e, ctx).is_none()),
        Expr::IsNotNull(e) => Some(eval_value(e, ctx).is_some()),
        Expr::In(e, list) => {
            let v = eval_value(e, ctx)?;
            Some(list.iter().any(|item| item == &v))
        }
        Expr::Not(e) => eval_ast(e, ctx).map(|b| !b),
        Expr::And(a, b) => Some(eval_ast(a, ctx)? && eval_ast(b, ctx)?),
        Expr::Or(a, b) => Some(eval_ast(a, ctx)? || eval_ast(b, ctx)?),
        Expr::Cmp(a, op, b) => {
            let left = eval_value(a, ctx)?;
            let right = eval_value(b, ctx)?;
            Some(compare(&left, &right, *op))
        }
    }
}

fn eval_value(expr: &Expr, ctx: &ExprCtx<'_>) -> Option<String> {
    match expr {
        Expr::Literal(s) => Some(s.clone()),
        Expr::Ident(id) => {
            if let Some(stripped) = id.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                return ctx.settings.get(stripped).cloned();
            }
            resolve_term(id, ctx)
        }
        _ => None,
    }
}

fn compare(left: &str, right: &str, op: CmpOp) -> bool {
    if let (Ok(l), Ok(r)) = (left.parse::<f64>(), right.parse::<f64>()) {
        return match op {
            CmpOp::Eq => (l - r).abs() < f64::EPSILON,
            CmpOp::Ne => (l - r).abs() >= f64::EPSILON,
            CmpOp::Lt => l < r,
            CmpOp::Le => l <= r,
            CmpOp::Gt => l > r,
            CmpOp::Ge => l >= r,
        };
    }
    match op {
        CmpOp::Eq => left == right,
        CmpOp::Ne => left != right,
        CmpOp::Lt => left < right,
        CmpOp::Le => left <= right,
        CmpOp::Gt => left > right,
        CmpOp::Ge => left >= right,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::facts::{kind, FactStore};

    #[test]
    fn referenced_aliases_extracts_idents_and_skips_settings() {
        assert_eq!(
            referenced_aliases("m.loader = 'fabric' AND e.loader != m.loader"),
            vec!["e".to_string(), "m".to_string()]
        );
        // Settings placeholders / aliasless terms are not aliases.
        assert!(
            referenced_aliases("s.trust_score < {settings.well_identified_trust}")
                == vec!["s".to_string()]
        );
        assert!(referenced_aliases("attr:class = 'x' AND subject IS NOT NULL").is_empty());
    }

    #[test]
    fn having_can_reference_computed_vars() {
        let bindings: BTreeMap<String, &Fact> = BTreeMap::new();
        let settings = BTreeMap::new();
        let mut vars = BTreeMap::new();
        vars.insert("count".to_string(), "3".to_string());
        let ctx = ExprCtx {
            bindings: &bindings,
            settings: &settings,
            vars: Some(&vars),
        };
        assert!(eval_bool("count >= 3", &ctx));
        assert!(!eval_bool("count >= 4", &ctx));
    }

    #[test]
    fn parses_in_and_comparison() {
        let mut store = FactStore::new();
        store
            .fact("t", kind::MOD)
            .subject("alpha")
            .attr("loader", "forge")
            .emit();
        let fact = &store.all()[0];
        let mut bindings = BTreeMap::new();
        bindings.insert("m".into(), fact);
        let settings = BTreeMap::new();
        let ctx = ExprCtx {
            bindings: &bindings,
            settings: &settings,
            vars: None,
        };
        assert!(eval_bool(
            "m.loader IN ('fabric', 'quilt', 'forge') AND m.loader != 'fabric'",
            &ctx
        ));
    }

    #[test]
    fn trust_score_comparison_and_match_on() {
        let mut store = FactStore::new();
        store
            .fact("sbom", kind::SBOM)
            .subject("shady.jar")
            .attr("trust_score", 10_i64)
            .emit();
        store
            .fact("security", kind::USES_PROCESS_SPAWN)
            .subject("shady.jar")
            .attr("archive", "shady.jar")
            .emit();
        let sbom = &store.all()[0];
        let sec = &store.all()[1];
        let mut bindings = BTreeMap::new();
        bindings.insert("s".into(), sbom);
        bindings.insert("related".into(), sec);
        let settings = BTreeMap::new();
        let ctx = ExprCtx {
            bindings: &bindings,
            settings: &settings,
            vars: None,
        };
        assert!(eval_bool("s.attr:trust_score < 60", &ctx));
        assert!(eval_bool("s.subject = related.attr:archive", &ctx));
    }

    #[test]
    fn settings_placeholder_in_comparison() {
        let mut store = FactStore::new();
        store
            .fact("sbom", kind::SBOM)
            .subject("shady.jar")
            .attr("trust_score", 10_i64)
            .emit();
        let fact = &store.all()[0];
        let mut bindings = BTreeMap::new();
        bindings.insert("s".into(), fact);
        let mut settings = BTreeMap::new();
        settings.insert("settings.sbom.well_identified_trust".into(), "60".into());
        let ctx = ExprCtx {
            bindings: &bindings,
            settings: &settings,
            vars: None,
        };
        assert!(eval_bool(
            "s.attr:trust_score < {settings.sbom.well_identified_trust}",
            &ctx
        ));
        assert!(!eval_bool("s.subject = related.attr:archive", &ctx));
    }

    #[test]
    fn is_not_null_detects_subject() {
        let mut store = FactStore::new();
        store.fact("t", kind::MOD).subject("alpha").emit();
        let fact = &store.all()[0];
        let mut bindings = BTreeMap::new();
        bindings.insert("m".into(), fact);
        let settings = BTreeMap::new();
        let ctx = ExprCtx {
            bindings: &bindings,
            settings: &settings,
            vars: None,
        };
        assert!(eval_bool("m.subject IS NOT NULL", &ctx));
    }
}