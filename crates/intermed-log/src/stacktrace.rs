//! Structured multiline stack-trace parsing.
//!
//! The per-line signal scan in [`crate`] classifies *individual* lines, but a Java
//! crash is a multi-line structure: an exception header, its `at …` frames, a
//! `… N more` elision, and a `Caused by:` chain. Reconstructing that structure
//! lets us (a) carry the real exception + top frame as a crash signal's excerpt
//! instead of one truncated line, and (b) pull out which *mods* a crash
//! structurally names — mixin config files (`somemod.mixins.json`) and explicit
//! `mod 'x'` messages — which is what feeds the `log_mentions_mod` correlation.
//!
//! Parsing is tolerant: lines may carry a logger prefix (`[12:00:00] [Server
//! thread/ERROR]: `) before the exception or frame, and crash-report `.txt`s
//! carry none. We locate the exception/frame token within the line rather than
//! anchoring to column zero.

use std::sync::OnceLock;

use regex::Regex;

/// One parsed exception (a top-level throw or a `Caused by:` link).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exception {
    /// Fully-qualified throwable class, e.g. `java.lang.NullPointerException`.
    pub class: String,
    /// Message after the class, if any.
    pub message: Option<String>,
    /// `at …` frame bodies belonging to *this* exception link, in order.
    pub frames: Vec<String>,
}

/// A reconstructed stack trace: the thrown exception, its frames, and its
/// `Caused by:` chain, plus the mods it structurally names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stacktrace {
    /// 0-based line number of the exception header.
    pub line: usize,
    /// The top-level thrown exception (with its own frames).
    pub exception: Exception,
    /// The `Caused by:` chain, outermost first (each with its own frames).
    pub caused_by: Vec<Exception>,
    /// Distinct mods this trace names, with how they were found.
    pub mod_refs: Vec<ModRef>,
}

/// A mod a stack trace structurally names, and the evidence kind it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModRef {
    pub mod_id: String,
    /// `mixin-config` (a `*.mixins.json` reference) or `message` (an explicit
    /// `mod 'x'` / `Failed to load mod x` phrase).
    pub via: &'static str,
}

struct Patterns {
    exception: Regex,
    frame: Regex,
    more: Regex,
    caused_by: Regex,
    mixin_config: Regex,
    mod_phrase: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        // Optional logger prefix, then a throwable class (+ optional message).
        exception: Regex::new(
            r"^(?:.*?[\]:>]\s+)?([a-zA-Z_][\w.$]*(?:Exception|Error|Throwable))(?::\s*(.*))?\s*$",
        )
        .unwrap(),
        frame: Regex::new(r"^\s*(?:.*?[\]:>]\s+)?at\s+(.+?)\s*$").unwrap(),
        more: Regex::new(r"^\s*\.\.\.\s+\d+\s+more\s*$").unwrap(),
        caused_by: Regex::new(
            r"^(?:.*?[\]:>]\s+)?Caused by:\s*([a-zA-Z_][\w.$]*(?:Exception|Error|Throwable))(?::\s*(.*))?\s*$",
        )
        .unwrap(),
        // A mixin config file: `somemod.mixins.json` or `mixins.somemod.json`.
        mixin_config: Regex::new(r"([a-zA-Z0-9_][\w-]*)\.mixins\.json|mixins\.([a-zA-Z0-9_][\w-]*)\.json")
            .unwrap(),
        // Explicit mod-id phrases loaders emit on failure.
        mod_phrase: Regex::new(
            r#"(?:mod\s+['"]([a-zA-Z0-9_][\w-]*)['"]|Failed to load mod\s+([a-zA-Z0-9_][\w-]*)|for mod\s+([a-zA-Z0-9_][\w-]*)|mod id\s+['"]?([a-zA-Z0-9_][\w-]*))"#,
        )
        .unwrap(),
    })
}

/// `Caused by:` first, then a bare exception header. Order matters: a caused-by
/// line also matches the looser exception regex.
fn match_exception(line: &str, p: &Patterns) -> Option<(Exception, bool)> {
    if let Some(c) = p.caused_by.captures(line) {
        return Some((exception_from(&c), true));
    }
    p.exception
        .captures(line)
        .map(|c| (exception_from(&c), false))
}

fn exception_from(c: &regex::Captures<'_>) -> Exception {
    Exception {
        class: c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default(),
        message: c
            .get(2)
            .map(|m| m.as_str().trim())
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        frames: Vec::new(),
    }
}

/// Parse every stack trace in `text`.
pub fn parse_stacktraces(text: &str) -> Vec<Stacktrace> {
    let p = patterns();
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<Stacktrace> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        // A `Caused by:` with no preceding trace is malformed but still useful;
        // `match_exception` accepts it, so it becomes its own top-level trace.
        let Some((mut exception, _is_caused_by)) = match_exception(lines[i], p) else {
            i += 1;
            continue;
        };
        let header_line = i;
        let mut caused_by: Vec<Exception> = Vec::new();
        i += 1;
        // Consume frames / `... N more` / nested `Caused by:` belonging to this
        // trace. Frames are routed to the currently-open exception link so a
        // caused-by's frames are attributed to it, not the top exception.
        while i < lines.len() {
            let line = lines[i];
            if let Some(c) = p.frame.captures(line) {
                let sink = caused_by.last_mut().unwrap_or(&mut exception);
                sink.frames.push(c[1].to_string());
                i += 1;
            } else if p.more.is_match(line) {
                i += 1; // `... N more`
            } else if let Some(cc) = p.caused_by.captures(line) {
                caused_by.push(exception_from(&cc));
                i += 1;
            } else {
                break;
            }
        }
        let mut trace = Stacktrace {
            line: header_line,
            exception,
            caused_by,
            mod_refs: Vec::new(),
        };
        trace.mod_refs = extract_mod_refs(&trace, p);
        out.push(trace);
    }
    out
}

/// Pull distinct mod references from a trace's exception text and frames.
fn extract_mod_refs(trace: &Stacktrace, p: &Patterns) -> Vec<ModRef> {
    let mut found: Vec<ModRef> = Vec::new();
    let push = |mod_id: String, via: &'static str, found: &mut Vec<ModRef>| {
        if !mod_id.is_empty() && !found.iter().any(|r| r.mod_id == mod_id) {
            found.push(ModRef { mod_id, via });
        }
    };

    let texts = trace_texts(trace);
    for text in &texts {
        for caps in p.mixin_config.captures_iter(text) {
            let id = caps
                .get(1)
                .or_else(|| caps.get(2))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            push(id, "mixin-config", &mut found);
        }
        for caps in p.mod_phrase.captures_iter(text) {
            let id = (1..=4)
                .find_map(|g| caps.get(g))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            push(id, "message", &mut found);
        }
    }
    found
}

/// All searchable text of a trace: every exception link's message and frames.
fn trace_texts(trace: &Stacktrace) -> Vec<String> {
    let mut texts = Vec::new();
    for ex in std::iter::once(&trace.exception).chain(trace.caused_by.iter()) {
        if let Some(m) = &ex.message {
            texts.push(m.clone());
        }
        texts.extend(ex.frames.iter().cloned());
    }
    texts
}

#[cfg(test)]
mod tests {
    use super::*;

    const CRASH: &str = "\
[12:00:00] [Server thread/ERROR]: java.lang.RuntimeException: Mixin apply failed somemod.mixins.json:SomeMixin
\tat org.spongepowered.asm.mixin.transformer.MixinProcessor.applyMixins(MixinProcessor.java:100)
\tat somemod.SomeClass.method(SomeClass.java:42)
\t... 12 more
Caused by: java.lang.NullPointerException: tried to call x on null
\tat othermod.Helper.run(Helper.java:7)
";

    #[test]
    fn parses_exception_frames_and_caused_by() {
        let traces = parse_stacktraces(CRASH);
        assert_eq!(traces.len(), 1);
        let t = &traces[0];
        assert_eq!(t.exception.class, "java.lang.RuntimeException");
        assert!(t.exception.message.as_deref().unwrap().contains("Mixin apply failed"));
        assert_eq!(t.exception.frames.len(), 2, "frames: {:?}", t.exception.frames);
        assert!(t.exception.frames[0].contains("MixinProcessor.applyMixins"));
        assert_eq!(t.caused_by.len(), 1);
        assert_eq!(t.caused_by[0].class, "java.lang.NullPointerException");
        assert_eq!(t.caused_by[0].frames.len(), 1, "caused-by frames routed correctly");
    }

    #[test]
    fn extracts_mod_from_mixin_config() {
        let traces = parse_stacktraces(CRASH);
        let ids: Vec<&str> = traces[0].mod_refs.iter().map(|r| r.mod_id.as_str()).collect();
        assert!(ids.contains(&"somemod"), "mod_refs: {ids:?}");
        assert_eq!(traces[0].mod_refs[0].via, "mixin-config");
    }

    #[test]
    fn extracts_mod_from_explicit_phrase() {
        let text = "[ERROR]: net.fabricmc.loader.ModResolutionException: Could not execute entrypoint for mod examplemod\n\tat foo.Bar.baz(Bar.java:1)\n";
        let traces = parse_stacktraces(text);
        let ids: Vec<&str> = traces[0].mod_refs.iter().map(|r| r.mod_id.as_str()).collect();
        assert!(ids.contains(&"examplemod"), "mod_refs: {ids:?}");
    }

    #[test]
    fn plain_log_lines_yield_no_traces() {
        let text = "[INFO] starting server\n[INFO] done\n";
        assert!(parse_stacktraces(text).is_empty());
    }

    #[test]
    fn crash_report_without_logger_prefix_parses() {
        let text = "java.lang.StackOverflowError\n\tat a.B.c(B.java:1)\n\tat d.E.f(E.java:2)\n";
        let traces = parse_stacktraces(text);
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].exception.class, "java.lang.StackOverflowError");
        assert_eq!(traces[0].exception.frames.len(), 2);
    }
}
