//! IR → Soufflé Datalog translator (plan: replace `datalog_codegen`).
//!
//! Lowers a [`RelExpr`] to a Datalog rule over a *generic* fact model — the same
//! flat foreign-key shape as the columnar/DuckDB schema:
//!
//! ```text
//! .decl fact(id:number, kind:symbol, subject:symbol)
//! .decl fact_attr(id:number, key:symbol, val:symbol)
//! ```
//!
//! so any `Scan`+`Filter` rule maps to one Datalog clause without per-rule hand
//! coding (unlike the old 3-rule `datalog_codegen`). The matched-id output relation
//! is then read back and findings are emitted by the interpreter's `build_finding`
//! (matching in Datalog, emission reused — "integrate the best").

use crate::ir::{CmpOp, RelExpr, ScalarValue};

/// The shared declarations every generated program needs (emitted once).
pub const FACT_SCHEMA: &str = "\
.decl fact(id:number, kind:symbol, subject:symbol)
.decl fact_attr(id:number, key:symbol, val:symbol)
.input fact
.input fact_attr
";

/// Escape a Soufflé symbol literal (quotes inside `"..."`).
fn esc(s: &str) -> String {
    s.replace('"', "\\\"")
}

fn scalar(v: &ScalarValue) -> String {
    match v {
        ScalarValue::Str(s) => esc(s),
        ScalarValue::Int(i) => i.to_string(),
        ScalarValue::Float(f) => f.to_string(),
        ScalarValue::Bool(b) => b.to_string(),
    }
}

/// Collect the base `Scan` kind and the conjunctive `Eq`/`Ne` filters of a linear
/// `Scan`(`Filter`*) plan. Returns `None` for shapes Datalog can't express here
/// (joins, aggregates, non-eq/ne comparisons).
fn flatten<'a>(
    expr: &'a RelExpr,
    filters: &mut Vec<(&'a str, CmpOp, &'a ScalarValue)>,
) -> Option<&'a str> {
    match expr {
        RelExpr::Scan { kind } => Some(kind),
        RelExpr::Filter { input, predicate } => {
            // Only Eq/Ne lower cleanly to the generic fact_attr model.
            if !matches!(predicate.op, CmpOp::Eq | CmpOp::Ne) {
                return None;
            }
            filters.push((predicate.column.as_str(), predicate.op, &predicate.value));
            flatten(input, filters)
        }
        // Projection is irrelevant to *which ids* match.
        RelExpr::Project { input, .. } => flatten(input, filters),
        _ => None,
    }
}

/// Lower a `Scan`+`Filter` plan to a Datalog rule selecting matching fact ids into
/// relation `rel`. Returns `None` for shapes not expressible here.
pub fn to_datalog(expr: &RelExpr, rel: &str) -> Option<String> {
    let mut filters = Vec::new();
    let kind = flatten(expr, &mut filters)?;

    let mut body = vec![format!("fact(id, \"{}\", _)", esc(kind))];
    for (col, op, val) in &filters {
        let v = scalar(val);
        let atom = match *col {
            "subject" => format!("fact(id, _, \"{v}\")"),
            "kind" => format!("fact(id, \"{v}\", _)"),
            "fact_id" => continue, // the id itself
            attr => format!("fact_attr(id, \"{}\", \"{v}\")", esc(attr)),
        };
        match op {
            CmpOp::Eq => body.push(atom),
            // `where_not`: the fact must NOT have that (attr,val). For subject/kind a
            // direct inequality; for an attribute, negate the membership atom.
            CmpOp::Ne => match *col {
                "subject" => body.push(format!("fact(id, _, s), s != \"{v}\"")),
                "kind" => body.push(format!("fact(id, k, _), k != \"{v}\"")),
                attr => body.push(format!("!fact_attr(id, \"{}\", \"{v}\")", esc(attr))),
            },
            _ => return None,
        }
    }

    Some(format!(
        ".decl {rel}(id:number)\n.output {rel}\n{rel}(id) :- {}.\n",
        body.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CmpOp, Predicate, RelExpr, ScalarValue};

    fn eq(col: &str, v: &str) -> Predicate {
        Predicate {
            column: col.into(),
            op: CmpOp::Eq,
            value: ScalarValue::Str(v.into()),
        }
    }

    #[test]
    fn fact_finding_attr_filter() {
        let ir = RelExpr::scan("resource_collision").filter(eq("class", "json-merge-candidate"));
        let dl = to_datalog(&ir, "r_test").unwrap();
        assert!(dl.contains("fact(id, \"resource_collision\", _)"));
        assert!(dl.contains("fact_attr(id, \"class\", \"json-merge-candidate\")"));
        assert!(dl.contains(".output r_test"));
    }

    #[test]
    fn subject_and_negation() {
        let ir = RelExpr::scan("mod")
            .filter(eq("subject", "sodium"))
            .filter(Predicate {
                column: "loader".into(),
                op: CmpOp::Ne,
                value: ScalarValue::Str("forge".into()),
            });
        let dl = to_datalog(&ir, "r").unwrap();
        assert!(dl.contains("fact(id, _, \"sodium\")"));
        assert!(dl.contains("!fact_attr(id, \"loader\", \"forge\")"));
    }

    #[test]
    fn unsupported_shapes_return_none() {
        let ir = RelExpr::scan("a").join(RelExpr::scan("b"), vec![("x".into(), "y".into())]);
        assert!(to_datalog(&ir, "r").is_none());
        // Non-eq comparison.
        let gt = RelExpr::scan("a").filter(Predicate {
            column: "n".into(),
            op: CmpOp::Gt,
            value: ScalarValue::Int(5),
        });
        assert!(to_datalog(&gt, "r").is_none());
    }
}
