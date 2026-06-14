//! Minimal Java class-file builders for security scanner tests.

/// Build a valid `.class` with only free-floating UTF-8 entries (no refs).
pub fn class_with_utf8_only(strings: &[&str]) -> Vec<u8> {
    let mut builder = CpBuilder::new("demo/Clazz");
    for s in strings {
        builder.push_utf8(s);
    }
    builder.finish()
}

/// Build a valid `.class` whose constant pool contains a `Class` entry.
pub fn class_with_class_ref(class_name: &str) -> Vec<u8> {
    let mut builder = CpBuilder::new("demo/Clazz");
    builder.push_class(class_name);
    builder.finish()
}

/// Build a valid `.class` with a `MethodRef` to `class#method(descriptor)`.
pub fn class_with_method_ref(class_name: &str, method_name: &str, descriptor: &str) -> Vec<u8> {
    let mut builder = CpBuilder::new("demo/Clazz");
    builder.push_method_ref(class_name, method_name, descriptor);
    builder.finish()
}

/// Build a valid `.class` whose pool holds `CONSTANT_String` literals — the form
/// produced by source string literals such as `Class.forName("…")` arguments.
pub fn class_with_string_constants(strings: &[&str]) -> Vec<u8> {
    let mut builder = CpBuilder::new("demo/Clazz");
    for s in strings {
        builder.push_string_constant(s);
    }
    builder.finish()
}

/// Build a valid `.class` combining method references and `CONSTANT_String`
/// literals — used to exercise reflection-corroborated detection.
pub fn class_with_refs_and_strings(
    method_refs: &[(&str, &str, &str)],
    strings: &[&str],
) -> Vec<u8> {
    let mut builder = CpBuilder::new("demo/Clazz");
    for (class_name, method_name, descriptor) in method_refs {
        builder.push_method_ref(class_name, method_name, descriptor);
    }
    for s in strings {
        builder.push_string_constant(s);
    }
    builder.finish()
}

/// Minimal class with only `this` / `super` entries — used for parser smoke tests.
pub fn minimal_class() -> Vec<u8> {
    CpBuilder::new("demo/Clazz").finish()
}

struct CpBuilder {
    this_class: String,
    entries: Vec<Vec<u8>>,
}

impl CpBuilder {
    fn new(this_class: &str) -> Self {
        Self {
            this_class: this_class.to_string(),
            entries: Vec::new(),
        }
    }

    fn push_utf8(&mut self, value: &str) -> u16 {
        let mut entry = vec![1u8];
        let bytes = value.as_bytes();
        entry.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        entry.extend_from_slice(bytes);
        self.push_entry(entry)
    }

    fn push_string_constant(&mut self, value: &str) -> u16 {
        let utf8_idx = self.push_utf8(value);
        let mut entry = vec![8u8]; // CONSTANT_String
        entry.extend_from_slice(&utf8_idx.to_be_bytes());
        self.push_entry(entry)
    }

    fn push_class(&mut self, class_name: &str) -> u16 {
        let name_idx = self.push_utf8(class_name);
        let mut entry = vec![7u8];
        entry.extend_from_slice(&name_idx.to_be_bytes());
        self.push_entry(entry)
    }

    fn push_name_and_type(&mut self, name: &str, descriptor: &str) -> u16 {
        let name_idx = self.push_utf8(name);
        let desc_idx = self.push_utf8(descriptor);
        let mut entry = vec![12u8];
        entry.extend_from_slice(&name_idx.to_be_bytes());
        entry.extend_from_slice(&desc_idx.to_be_bytes());
        self.push_entry(entry)
    }

    fn push_method_ref(&mut self, class_name: &str, method_name: &str, descriptor: &str) -> u16 {
        let class_idx = self.push_class(class_name);
        let nat_idx = self.push_name_and_type(method_name, descriptor);
        let mut entry = vec![10u8];
        entry.extend_from_slice(&class_idx.to_be_bytes());
        entry.extend_from_slice(&nat_idx.to_be_bytes());
        self.push_entry(entry)
    }

    fn push_entry(&mut self, entry: Vec<u8>) -> u16 {
        let idx = (self.entries.len() + 1) as u16;
        self.entries.push(entry);
        idx
    }

    fn finish(mut self) -> Vec<u8> {
        let this_class = self.this_class.clone();
        let this_idx = self.push_utf8(&this_class);
        let super_name_idx = self.push_utf8("java/lang/Object");
        let this_class_idx = {
            let mut entry = vec![7u8];
            entry.extend_from_slice(&this_idx.to_be_bytes());
            self.push_entry(entry)
        };
        let super_class_idx = {
            let mut entry = vec![7u8];
            entry.extend_from_slice(&super_name_idx.to_be_bytes());
            self.push_entry(entry)
        };

        let cp_count = (self.entries.len() + 1) as u16;
        let mut out = Vec::new();
        out.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&52u16.to_be_bytes());
        out.extend_from_slice(&cp_count.to_be_bytes());
        for entry in self.entries {
            out.extend_from_slice(&entry);
        }
        out.extend_from_slice(&0x0021u16.to_be_bytes());
        out.extend_from_slice(&this_class_idx.to_be_bytes());
        out.extend_from_slice(&super_class_idx.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // interfaces
        out.extend_from_slice(&0u16.to_be_bytes()); // fields
        out.extend_from_slice(&0u16.to_be_bytes()); // methods
        out.extend_from_slice(&0u16.to_be_bytes()); // attributes
        out
    }
}
