use core::fmt;

#[derive(Clone)]
pub struct CanonicalText {
    text: String,
}

impl CanonicalText {
    pub fn new(text: String) -> Self {
        Self { text }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for CanonicalText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalText")
            .field("len", &self.text.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct CanonicalCsv {
    pub delimiter: u8,
    pub headers: Vec<String>,
    pub records: Vec<Vec<String>>,
}

impl fmt::Debug for CanonicalCsv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalCsv")
            .field("delimiter", &self.delimiter)
            .field("headers_len", &self.headers.len())
            .field("records", &self.records.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct CanonicalJson {
    pub value: serde_json::Value,
}

impl fmt::Debug for CanonicalJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalJson")
            .field("kind", &json_kind_name(&self.value))
            .finish()
    }
}

#[derive(Clone)]
pub struct CanonicalNdjson {
    pub values: Vec<serde_json::Value>,
}

impl fmt::Debug for CanonicalNdjson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalNdjson")
            .field("records", &self.values.len())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub enum CanonicalArtifact {
    Text(CanonicalText),
    Csv(CanonicalCsv),
    Json(CanonicalJson),
    Ndjson(CanonicalNdjson),
}

pub fn canonicalize_json_value(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            let mut old = std::mem::take(map);
            let mut keys = old.keys().cloned().collect::<Vec<_>>();
            keys.sort();

            let mut out = serde_json::Map::new();
            for k in keys {
                let mut vv = old.remove(&k).expect("key was present when enumerated");
                canonicalize_json_value(&mut vv);
                out.insert(k, vv);
            }
            *map = out;
        }
        serde_json::Value::Array(items) => {
            for item in items {
                canonicalize_json_value(item);
            }
        }
        _ => {}
    }
}

fn json_kind_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}
