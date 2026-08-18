//! Runtime-event normalization for Layer D.
//!
//! Physical lines are an input encoding, not the semantic unit. This module
//! groups logger records with their continuations and gives multiline and
//! flattened Java stack traces the same normalized representation.

use std::ops::Range;
use std::sync::OnceLock;

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::stacktrace::{Exception, Stacktrace, parse_stacktraces};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvent {
    /// Unique identity of this physical occurrence.
    pub occurrence_id: String,
    /// Content identity shared by equivalent normalized failures.
    pub semantic_fingerprint: String,
    /// Rebuild-stable crash family identity: deepest exception, normalized
    /// message, and class+method frames (no source lines or unstable wrappers).
    pub fuzzy_fingerprint: String,
    pub timestamp: Option<String>,
    pub thread: Option<String>,
    pub level: Option<String>,
    pub logger: Option<String>,
    pub message: String,
    pub continuation_lines: Vec<String>,
    pub exception_chain: Vec<ThrowableNode>,
    pub terminality: EventTerminality,
    /// One-based physical line in the source file.
    pub source_line: u32,
    /// Fragment within `source_line` after flattened-log normalization.
    pub source_fragment: u32,
}

/// Whether an event is evidence that the analyzed process actually terminated.
/// Log level and exception presence alone are insufficient: many launchers and
/// servers recover from ERROR records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EventTerminality {
    ProcessFatal,
    LoaderAbort,
    CrashReportRoot,
    WatchdogTermination,
    ServerStopped,
    Recovered,
    BackgroundError,
    #[default]
    Unknown,
}

impl EventTerminality {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcessFatal => "process-fatal",
            Self::LoaderAbort => "loader-abort",
            Self::CrashReportRoot => "crash-report-root",
            Self::WatchdogTermination => "watchdog-termination",
            Self::ServerStopped => "server-stopped",
            Self::Recovered => "recovered",
            Self::BackgroundError => "background-error",
            Self::Unknown => "unknown",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::ProcessFatal
                | Self::LoaderAbort
                | Self::CrashReportRoot
                | Self::WatchdogTermination
                | Self::ServerStopped
        )
    }
}

/// A normalized fragment which retains its physical source coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedLine {
    pub text: String,
    pub physical_line: u32,
    pub normalized_fragment: u32,
    pub byte_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThrowableNode {
    pub throwable_type: String,
    pub message: Option<String>,
    pub cause: Option<usize>,
    pub suppressed: bool,
    pub frames: Vec<StackFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackFrame {
    /// Loader module owner parsed from frames such as
    /// `TRANSFORMER/create@6.0.10/com.example.Class.method(...)`.
    pub module: Option<String>,
    pub class: String,
    pub method: String,
    pub source: Option<String>,
    pub line: Option<u32>,
    pub classification: FrameClassification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameClassification {
    Jdk,
    Minecraft,
    Framework,
    ModOrLibrary,
}

impl FrameClassification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jdk => "jdk",
            Self::Minecraft => "minecraft",
            Self::Framework => "framework",
            Self::ModOrLibrary => "mod-or-library",
        }
    }
}

struct Prefixes {
    standard: Regex,
    flattened: Regex,
    frame: Regex,
}

fn patterns() -> &'static Prefixes {
    static PATTERNS: OnceLock<Prefixes> = OnceLock::new();
    PATTERNS.get_or_init(|| Prefixes {
        standard: Regex::new(
            r"^\[(?P<time>[^]]+)\]\s+\[(?P<thread>[^]/\]]+)/(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\](?:\s+\[(?P<logger>[^]]+)\])?:?\s*(?P<message>.*)$",
        )
        .unwrap(),
        // A conservative expansion used only around unmistakable Java stack
        // tokens. It does not split ordinary prose containing the word "at".
        flattened: Regex::new(
            r"\s+(Caused by:|Suppressed:|at\s+[A-Za-z_$][A-Za-z0-9_.$]*\.[A-Za-z_$][A-Za-z0-9_$<>]*)",
        )
        .unwrap(),
        frame: Regex::new(
            r"^(?P<class>[A-Za-z_$][A-Za-z0-9_.$]*)\.(?P<method>[A-Za-z_$][A-Za-z0-9_$<>]*)\((?P<source>[^():]+)?(?::(?P<line>\d+))?\)$",
        )
        .unwrap(),
    })
}

fn hash_field(digest: &mut Sha256, tag: &str, value: &[u8]) {
    digest.update((tag.len() as u32).to_be_bytes());
    digest.update(tag.as_bytes());
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn finish_digest(digest: Sha256) -> String {
    format!("{:x}", digest.finalize())
}

fn semantic_fingerprint(event: &RuntimeEvent) -> String {
    let mut digest = Sha256::new();
    hash_field(&mut digest, "schema", b"runtime-semantic-v1");
    if event.exception_chain.is_empty() {
        hash_field(
            &mut digest,
            "level",
            event.level.as_deref().unwrap_or("").as_bytes(),
        );
        hash_field(
            &mut digest,
            "logger",
            event.logger.as_deref().unwrap_or("").as_bytes(),
        );
        hash_field(&mut digest, "message", event.message.as_bytes());
        for (index, line) in event.continuation_lines.iter().enumerate() {
            hash_field(
                &mut digest,
                &format!("continuation:{index}"),
                line.as_bytes(),
            );
        }
    } else {
        for (node_index, node) in event.exception_chain.iter().enumerate() {
            hash_field(
                &mut digest,
                &format!("throwable:{node_index}:type"),
                node.throwable_type.as_bytes(),
            );
            hash_field(
                &mut digest,
                &format!("throwable:{node_index}:message"),
                node.message.as_deref().unwrap_or("").as_bytes(),
            );
            hash_field(
                &mut digest,
                &format!("throwable:{node_index}:cause"),
                node.cause
                    .map(|value| value.to_string())
                    .unwrap_or_default()
                    .as_bytes(),
            );
            hash_field(
                &mut digest,
                &format!("throwable:{node_index}:suppressed"),
                if node.suppressed { b"true" } else { b"false" },
            );
            for (frame_index, frame) in node.frames.iter().enumerate() {
                let prefix = format!("throwable:{node_index}:frame:{frame_index}");
                hash_field(
                    &mut digest,
                    &format!("{prefix}:class"),
                    frame.class.as_bytes(),
                );
                hash_field(
                    &mut digest,
                    &format!("{prefix}:method"),
                    frame.method.as_bytes(),
                );
                hash_field(
                    &mut digest,
                    &format!("{prefix}:source"),
                    frame.source.as_deref().unwrap_or("").as_bytes(),
                );
                hash_field(
                    &mut digest,
                    &format!("{prefix}:line"),
                    frame
                        .line
                        .map(|value| value.to_string())
                        .unwrap_or_default()
                        .as_bytes(),
                );
            }
        }
    }
    finish_digest(digest)
}

fn fuzzy_fingerprint(event: &RuntimeEvent) -> String {
    let mut digest = Sha256::new();
    hash_field(&mut digest, "schema", b"runtime-fuzzy-v1");
    let deepest = event.exception_chain.iter().rfind(|node| !node.suppressed);
    if let Some(node) = deepest {
        let family = node
            .throwable_type
            .rsplit('.')
            .next()
            .unwrap_or(&node.throwable_type);
        hash_field(&mut digest, "exception-family", family.as_bytes());
        hash_field(
            &mut digest,
            "normalized-message",
            normalize_unstable_message(node.message.as_deref().unwrap_or("")).as_bytes(),
        );
        for (index, frame) in node.frames.iter().enumerate() {
            hash_field(
                &mut digest,
                &format!("frame:{index}:class"),
                frame.class.as_bytes(),
            );
            hash_field(
                &mut digest,
                &format!("frame:{index}:method"),
                frame.method.as_bytes(),
            );
        }
    } else {
        hash_field(
            &mut digest,
            "message",
            normalize_unstable_message(&event.message).as_bytes(),
        );
    }
    finish_digest(digest)
}

fn normalize_unstable_message(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut in_digits = false;
    for ch in message.trim().chars() {
        if ch.is_ascii_digit() {
            if !in_digits {
                out.push('#');
            }
            in_digits = true;
        } else {
            in_digits = false;
            out.extend(ch.to_lowercase());
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn occurrence_id(event: &RuntimeEvent, source: &str, ordinal: usize) -> String {
    let normalized_source = source.replace('\\', "/");
    let mut source_digest = Sha256::new();
    hash_field(&mut source_digest, "source", normalized_source.as_bytes());
    let source_hash = finish_digest(source_digest);
    format!(
        "runtime-event:{}:{}:{}:{}",
        &event.semantic_fingerprint[..16],
        &source_hash[..12],
        event.source_line,
        ordinal
    )
}

fn fragment(
    line: &str,
    physical_line: u32,
    fragment: u32,
    base: usize,
    span: Range<usize>,
) -> NormalizedLine {
    let slice = &line[span.clone()];
    let leading = slice.len().saturating_sub(slice.trim_start().len());
    let trailing = slice.len().saturating_sub(slice.trim_end().len());
    let start = span.start.saturating_add(leading);
    let end = span.end.saturating_sub(trailing).max(start);
    NormalizedLine {
        text: line[span].trim_end().to_string(),
        physical_line,
        normalized_fragment: fragment,
        byte_range: base.saturating_add(start)..base.saturating_add(end),
    }
}

pub fn expand_flattened_lines(text: &str) -> Vec<NormalizedLine> {
    let may_be_flattened = text.contains("Exception") || text.contains("Error");
    let mut out = Vec::new();
    let mut base = 0usize;
    for (physical_index, raw) in text.split_inclusive('\n').enumerate() {
        let without_newline = raw.strip_suffix('\n').unwrap_or(raw);
        let line = without_newline
            .strip_suffix('\r')
            .unwrap_or(without_newline);
        let physical_line = u32::try_from(physical_index + 1).unwrap_or(u32::MAX);
        let mut spans = Vec::new();
        if may_be_flattened {
            let mut start = 0usize;
            for matched in patterns().flattened.find_iter(line) {
                let token_offset = matched
                    .as_str()
                    .find(|ch: char| !ch.is_whitespace())
                    .unwrap_or(0);
                let token_start = matched.start().saturating_add(token_offset);
                if token_start > start && !line[start..token_start].trim().is_empty() {
                    spans.push(start..token_start);
                }
                start = token_start;
            }
            if start < line.len() && !line[start..].trim().is_empty() {
                spans.push(start..line.len());
            }
        }
        if spans.is_empty() {
            spans.push(0..line.len());
        }
        for (fragment_index, span) in spans.into_iter().enumerate() {
            out.push(fragment(
                line,
                physical_line,
                u32::try_from(fragment_index).unwrap_or(u32::MAX),
                base,
                span,
            ));
        }
        base = base.saturating_add(raw.len());
    }
    // `split_inclusive` yields no row for an empty input.
    if text.is_empty() {
        out.clear();
    }
    out
}

fn is_exception_header(text: &str) -> bool {
    let head = text.split_once(':').map_or(text, |(head, _)| head);
    !head.contains(char::is_whitespace)
        && (head.ends_with("Exception") || head.ends_with("Error") || head.ends_with("Throwable"))
}

fn is_continuation(line: &NormalizedLine, event: &RuntimeEvent) -> bool {
    let trimmed = line.text.trim();
    trimmed.starts_with("at ")
        || trimmed.starts_with("Caused by:")
        || trimmed.starts_with("Suppressed:")
        || (trimmed.starts_with("...") && trimmed.ends_with(" more"))
        || line.text.chars().next().is_some_and(char::is_whitespace)
        || (matches!(event.level.as_deref(), Some("ERROR" | "FATAL"))
            && is_exception_header(trimmed))
}

pub fn normalize_events(text: &str, source: &str) -> Vec<RuntimeEvent> {
    let mut events = Vec::new();
    let mut current: Option<RuntimeEvent> = None;

    let flush = |event: &mut Option<RuntimeEvent>, out: &mut Vec<RuntimeEvent>| {
        if let Some(mut event) = event.take() {
            attach_exception_chain(&mut event);
            event.semantic_fingerprint = semantic_fingerprint(&event);
            event.fuzzy_fingerprint = fuzzy_fingerprint(&event);
            event.occurrence_id = occurrence_id(&event, source, out.len());
            out.push(event);
        }
    };

    for line in expand_flattened_lines(text) {
        if let Some(captures) = patterns().standard.captures(line.text.trim()) {
            flush(&mut current, &mut events);
            current = Some(RuntimeEvent {
                occurrence_id: String::new(),
                semantic_fingerprint: String::new(),
                fuzzy_fingerprint: String::new(),
                timestamp: captures.name("time").map(|m| m.as_str().to_string()),
                thread: captures.name("thread").map(|m| m.as_str().to_string()),
                level: captures.name("level").map(|m| m.as_str().to_string()),
                logger: captures.name("logger").map(|m| m.as_str().to_string()),
                message: captures
                    .name("message")
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default(),
                continuation_lines: Vec::new(),
                exception_chain: Vec::new(),
                terminality: EventTerminality::Unknown,
                source_line: line.physical_line,
                source_fragment: line.normalized_fragment,
            });
        } else if line.text.trim().is_empty() {
            flush(&mut current, &mut events);
        } else if current
            .as_ref()
            .is_some_and(|event| is_continuation(&line, event))
        {
            if let Some(event) = current.as_mut() {
                event.continuation_lines.push(line.text.trim().to_string());
            }
        } else {
            flush(&mut current, &mut events);
            current = Some(RuntimeEvent {
                occurrence_id: String::new(),
                semantic_fingerprint: String::new(),
                fuzzy_fingerprint: String::new(),
                timestamp: None,
                thread: None,
                level: None,
                logger: None,
                message: line.text.trim().to_string(),
                continuation_lines: Vec::new(),
                exception_chain: Vec::new(),
                terminality: EventTerminality::Unknown,
                source_line: line.physical_line,
                source_fragment: line.normalized_fragment,
            });
        }
    }
    flush(&mut current, &mut events);
    classify_terminalities(&mut events);
    events
}

fn classify_terminalities(events: &mut [RuntimeEvent]) {
    let texts = events
        .iter()
        .map(|event| {
            std::iter::once(event.message.as_str())
                .chain(event.continuation_lines.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join("\n")
                .to_ascii_lowercase()
        })
        .collect::<Vec<_>>();

    for index in 0..events.len() {
        let text = &texts[index];
        let has_failure = !events[index].exception_chain.is_empty()
            || matches!(events[index].level.as_deref(), Some("ERROR" | "FATAL"));
        if !has_failure {
            continue;
        }
        let later = &texts[index.saturating_add(1)..];
        let later_recovery = later.iter().any(|line| is_recovery_marker(line));
        let later_crash_report = later.iter().any(|line| is_crash_report_marker(line));
        let terminality = if is_background_error(text) {
            EventTerminality::BackgroundError
        } else if (text.contains("watchdog")
            || events[index]
                .thread
                .as_deref()
                .is_some_and(|thread| thread.to_ascii_lowercase().contains("watchdog"))
            || events[index]
                .logger
                .as_deref()
                .is_some_and(|logger| logger.to_ascii_lowercase().contains("watchdog")))
            && (text.contains("exception")
                || text.contains("server hang")
                || text.contains("single server tick")
                || !events[index].exception_chain.is_empty())
        {
            EventTerminality::WatchdogTermination
        } else if is_loader_abort(text) {
            EventTerminality::LoaderAbort
        } else if is_crash_report_marker(text) || later_crash_report {
            EventTerminality::CrashReportRoot
        } else if matches!(events[index].level.as_deref(), Some("FATAL"))
            || events[index].exception_chain.iter().any(|node| {
                node.throwable_type.ends_with("OutOfMemoryError")
                    || node.throwable_type.ends_with("VirtualMachineError")
            })
            || text.contains("a fatal error has been detected by the java runtime environment")
        {
            EventTerminality::ProcessFatal
        } else if later_recovery {
            EventTerminality::Recovered
        } else {
            EventTerminality::Unknown
        };
        events[index].terminality = terminality;
    }
}

fn is_recovery_marker(text: &str) -> bool {
    text.contains("done (")
        || text.contains("server started")
        || text.contains("minecraft started")
        || text.contains("successfully loaded")
        || text.contains("startup complete")
}

fn is_crash_report_marker(text: &str) -> bool {
    text.contains("crash report has been saved")
        || text.contains("preparing crash report")
        || text.contains("---- minecraft crash report ----")
        || text.contains("a fatal error has been detected by the java runtime")
}

fn is_loader_abort(text: &str) -> bool {
    text.contains("loading errors encountered")
        || text.contains("failed to start minecraft")
        || text.contains("mod loading has failed")
        || text.contains("could not execute entrypoint")
        || text.contains("missing or unsupported mandatory dependencies")
}

fn is_background_error(text: &str) -> bool {
    (text.contains("update") && (text.contains("check") || text.contains("checker")))
        || text.contains("telemetry")
        || text.contains("could not contact")
}

fn attach_exception_chain(event: &mut RuntimeEvent) {
    let text = std::iter::once(event.message.as_str())
        .chain(event.continuation_lines.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join("\n");
    let Some(trace) = parse_stacktraces(&text).into_iter().next() else {
        return;
    };
    event.exception_chain = throwable_chain(&trace);
}

fn throwable_chain(trace: &Stacktrace) -> Vec<ThrowableNode> {
    let exceptions = std::iter::once(&trace.exception)
        .chain(trace.caused_by.iter())
        .collect::<Vec<_>>();
    let mut nodes = exceptions
        .iter()
        .enumerate()
        .map(|(index, exception)| {
            throwable_node(
                exception,
                (index + 1 < exceptions.len()).then_some(index + 1),
                false,
            )
        })
        .collect::<Vec<_>>();
    nodes.extend(
        trace
            .suppressed
            .iter()
            .map(|exception| throwable_node(exception, None, true)),
    );
    nodes
}

fn throwable_node(exception: &Exception, cause: Option<usize>, suppressed: bool) -> ThrowableNode {
    ThrowableNode {
        throwable_type: exception.class.clone(),
        message: exception.message.clone(),
        cause,
        suppressed,
        frames: exception
            .frames
            .iter()
            .map(|frame| parse_frame(frame))
            .collect(),
    }
}

fn parse_frame(frame: &str) -> StackFrame {
    let trimmed = frame.trim().trim_start_matches("at ");
    // NeoForge/Forge append the source archive after the Java frame. Strip it
    // before looking for the module separator; otherwise the final `/` inside
    // `jar!/:version` is mistaken for the module boundary.
    let symbol_with_module = trimmed
        .split_once(" ~[")
        .or_else(|| trimmed.split_once(" ["))
        .map_or(trimmed, |(symbol, _)| symbol);
    let (module, symbol) = split_module_qualified_frame(symbol_with_module);
    let Some(captures) = patterns().frame.captures(symbol) else {
        return StackFrame {
            module,
            class: trimmed.to_string(),
            method: String::new(),
            source: None,
            line: None,
            classification: classify_frame(trimmed),
        };
    };
    let class = captures["class"].to_string();
    StackFrame {
        module,
        classification: classify_frame(&class),
        class,
        method: captures["method"].to_string(),
        source: captures.name("source").map(|m| m.as_str().to_string()),
        line: captures
            .name("line")
            .and_then(|m| m.as_str().parse::<u32>().ok()),
    }
}

fn split_module_qualified_frame(frame: &str) -> (Option<String>, &str) {
    let Some((prefix, symbol)) = frame.rsplit_once('/') else {
        return (None, frame);
    };
    if !symbol.contains('(') || !symbol.contains('.') {
        return (None, frame);
    }
    let module = prefix
        .rsplit('/')
        .next()
        .and_then(|segment| segment.split('@').next())
        .filter(|module| {
            !module.is_empty()
                && !matches!(
                    *module,
                    "minecraft" | "java.base" | "MC-BOOTSTRAP" | "TRANSFORMER"
                )
        })
        .map(str::to_string);
    (module, symbol)
}

fn classify_frame(class: &str) -> FrameClassification {
    if class.starts_with("java.")
        || class.starts_with("javax.")
        || class.starts_with("jdk.")
        || class.starts_with("sun.")
    {
        FrameClassification::Jdk
    } else if class.starts_with("net.minecraft.") || class.starts_with("com.mojang.") {
        FrameClassification::Minecraft
    } else if class.starts_with("net.minecraftforge.")
        || class.starts_with("net.neoforged.")
        || class.starts_with("net.fabricmc.")
        || class.starts_with("org.spongepowered.")
    {
        FrameClassification::Framework
    } else {
        FrameClassification::ModOrLibrary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiline_and_flattened_crash_normalize_to_same_exception_graph() {
        let multiline = "[12:00:00] [Render thread/ERROR]: net.minecraft.ReportedException: charTyped event handler\n\tat com.simibubi.create.AllKeys.isKeyDown(AllKeys.java:42)\nCaused by: java.lang.IllegalStateException: Encountered GL error off-thread\n\tat com.example.cdg.EntityFilterItem.appendHoverText(EntityFilterItem.java:77)";
        let flattened = "[12:00:00] [Render thread/ERROR]: net.minecraft.ReportedException: charTyped event handler at com.simibubi.create.AllKeys.isKeyDown(AllKeys.java:42) Caused by: java.lang.IllegalStateException: Encountered GL error off-thread at com.example.cdg.EntityFilterItem.appendHoverText(EntityFilterItem.java:77)";
        let a = normalize_events(multiline, "latest.log");
        let b = normalize_events(flattened, "latest.log");
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_eq!(a[0].exception_chain, b[0].exception_chain);
        assert_eq!(a[0].semantic_fingerprint, b[0].semantic_fingerprint);
        assert_eq!(
            a[0].exception_chain.last().unwrap().throwable_type,
            "java.lang.IllegalStateException"
        );
    }

    #[test]
    fn info_initialization_is_a_plain_non_exception_event() {
        let events = normalize_events(
            "[12:00:00] [Render thread/INFO]: Create 6.0.10 initializing!",
            "latest.log",
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].level.as_deref(), Some("INFO"));
        assert!(events[0].exception_chain.is_empty());
    }

    #[test]
    fn repeated_occurrences_are_distinct_but_semantically_equal() {
        let line = "[12:00:00] [main/ERROR]: java.lang.IllegalStateException: boom";
        let events = normalize_events(&format!("{line}\n{line}"), "latest.log");
        assert_eq!(events.len(), 2);
        assert_ne!(events[0].occurrence_id, events[1].occurrence_id);
        assert_eq!(
            events[0].semantic_fingerprint,
            events[1].semantic_fingerprint
        );
    }

    #[test]
    fn source_locator_is_part_of_occurrence_not_semantics() {
        let line = "[12:00:00] [main/ERROR]: java.lang.IllegalStateException: boom";
        let a = normalize_events(line, "latest.log");
        let b = normalize_events(line, "crash-reports/crash.txt");
        assert_ne!(a[0].occurrence_id, b[0].occurrence_id);
        assert_eq!(a[0].semantic_fingerprint, b[0].semantic_fingerprint);
    }

    #[test]
    fn fuzzy_fingerprint_ignores_wrappers_lines_and_unstable_numbers() {
        let a = normalize_events(
            "[12:00:00] [main/FATAL]: net.minecraft.ReportedException: wrapper 10\n\tat wrapper.Host.run(Host.java:10)\nCaused by: java.lang.IllegalStateException: GLFW error 65539\n\tat example.Mod.tick(Mod.java:20)",
            "latest.log",
        );
        let b = normalize_events(
            "[12:00:01] [main/FATAL]: java.lang.RuntimeException: rebuilt wrapper 99\n\tat other.Wrapper.call(Wrapper.java:500)\nCaused by: java.lang.IllegalStateException: GLFW error 12345\n\tat example.Mod.tick(Mod.java:900)",
            "crash-reports/new.txt",
        );
        assert_ne!(a[0].semantic_fingerprint, b[0].semantic_fingerprint);
        assert_eq!(a[0].fuzzy_fingerprint, b[0].fuzzy_fingerprint);
    }

    #[test]
    fn tagged_hashing_distinguishes_field_boundaries() {
        let a = normalize_events("[12:00:00] [main/ERROR] [ab]: c", "latest.log");
        let b = normalize_events("[12:00:00] [main/ERROR] [a]: bc", "latest.log");
        assert_ne!(a[0].semantic_fingerprint, b[0].semantic_fingerprint);
    }

    #[test]
    fn flattened_fragments_keep_the_physical_line() {
        let text = "[12:00:00] [main/ERROR]: java.lang.IllegalStateException: boom at com.example.Mod.run(Mod.java:1) Caused by: java.lang.Error: root at com.example.Mod.root(Mod.java:2)";
        let lines = expand_flattened_lines(text);
        assert!(lines.len() >= 4);
        assert!(lines.iter().all(|line| line.physical_line == 1));
        assert_eq!(
            lines
                .iter()
                .map(|line| line.normalized_fragment)
                .collect::<Vec<_>>(),
            (0..u32::try_from(lines.len()).unwrap()).collect::<Vec<_>>()
        );
        let events = normalize_events(text, "latest.log");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source_line, 1);
    }

    #[test]
    fn unrelated_unprefixed_lines_do_not_become_continuations() {
        let events = normalize_events(
            "[12:00:00] [main/INFO]: Starting Minecraft\nLauncher message without a prefix\nAnother launcher message",
            "launcher.log",
        );
        assert_eq!(events.len(), 3);
        assert!(
            events
                .iter()
                .all(|event| event.continuation_lines.is_empty())
        );
    }

    #[test]
    fn error_followed_by_done_is_recovered_not_terminal() {
        let events = normalize_events(
            "[12:00:00] [main/ERROR]: java.lang.IllegalStateException: optional failure\n[12:00:01] [Server thread/INFO]: Done (2.1s)! For help, type help",
            "latest.log",
        );
        assert_eq!(events[0].terminality, EventTerminality::Recovered);
        assert!(!events[0].terminality.is_terminal());
    }

    #[test]
    fn fatal_with_saved_crash_report_is_terminal() {
        let events = normalize_events(
            "[12:00:00] [main/FATAL]: java.lang.IllegalStateException: boom\n[12:00:01] [main/ERROR]: This crash report has been saved to: crash.txt",
            "latest.log",
        );
        assert_eq!(events[0].terminality, EventTerminality::CrashReportRoot);
        assert!(events[0].terminality.is_terminal());
    }

    #[test]
    fn watchdog_exception_is_terminal() {
        let events = normalize_events(
            "[12:00:00] [Server Watchdog/FATAL]: java.lang.Error: Watching Server\n\tat net.minecraft.server.dedicated.ServerWatchdog.run(ServerWatchdog.java:1)",
            "latest.log",
        );
        assert_eq!(events[0].terminality, EventTerminality::WatchdogTermination);
    }

    #[test]
    fn update_check_failure_is_background() {
        let events = normalize_events(
            "[12:00:00] [Update thread/ERROR]: java.io.IOException: update check failed",
            "latest.log",
        );
        assert_eq!(events[0].terminality, EventTerminality::BackgroundError);
    }

    #[test]
    fn datapack_error_followed_by_startup_is_recovered() {
        let events = normalize_events(
            "[12:00:00] [Server thread/ERROR]: java.lang.IllegalArgumentException: datapack parse error\n[12:00:01] [Server thread/INFO]: Done (4.0s)! For help, type help",
            "latest.log",
        );
        assert_eq!(events[0].terminality, EventTerminality::Recovered);
    }

    #[test]
    fn neoforge_module_qualified_frame_preserves_symbol_and_mod_owner() {
        let frame = parse_frame(
            "TRANSFORMER/createdieselgenerators@1.3.15/com.jesz.createdieselgenerators.EntityFilterItem.appendHoverText(EntityFilterItem.java:46) ~[createdieselgenerators.jar%23521!/:?]",
        );
        assert_eq!(frame.module.as_deref(), Some("createdieselgenerators"));
        assert_eq!(
            frame.class,
            "com.jesz.createdieselgenerators.EntityFilterItem"
        );
        assert_eq!(frame.method, "appendHoverText");
        assert_eq!(frame.line, Some(46));
        assert_eq!(frame.classification, FrameClassification::ModOrLibrary);
    }
}
