//! Surgical frontmatter edits: `props set` rewrites ONLY the `---` block,
//! preserving every other byte of the note.

use crate::error::{Result, StoneError};
use crate::parser::parse_frontmatter;
use serde_yaml::{Mapping as YamlMap, Value as YamlValue};

/// Set `key = value` in a note's YAML frontmatter.
/// `value` is parsed as YAML (so `"42"`→number unless quoted in the arg —
/// shell callers pass e.g. `"\"42\""` for a string).
pub fn set_prop(text: &str, key: &str, value: &str) -> Result<String> {
    let yaml_val: YamlValue = serde_yaml::from_str(value)
        .unwrap_or_else(|_| YamlValue::String(value.to_string()));
    set_prop_value(text, key, yaml_val)
}

/// Remove a property.
pub fn remove_prop(text: &str, key: &str) -> Result<String> {
    set_prop_value(text, key, YamlValue::Null)
}

fn set_prop_value(text: &str, key: &str, value: YamlValue) -> Result<String> {
    let fm = parse_frontmatter(text);
    let mut map: YamlMap = match &fm {
        Some(f) => match &f.value {
            Some(YamlValue::Mapping(m)) => m.clone(),
            _ => YamlMap::new(),
        },
        None => YamlMap::new(),
    };
    if value.is_null() {
        map.remove(YamlValue::String(key.to_string()));
    } else {
        map.insert(YamlValue::String(key.to_string()), value);
    }
    let body = match &fm {
        Some(f) => &text[f.span.end..],
        None => text,
    };
    if map.is_empty() {
        if fm.is_none() {
            return Ok(text.to_string());
        }
        // fm removed entirely
        return Ok(body.to_string());
    }
    let yaml = serde_yaml::to_string(&YamlValue::Mapping(map)).map_err(StoneError::Yaml)?;
    Ok(format!("---\n{yaml}---\n{body}"))
}

/// Get a property's rendered value.
pub fn get_prop(text: &str, key: &str) -> Option<String> {
    let fm = parse_frontmatter(text)?;
    let map = fm.value?.as_mapping()?.clone();
    let v = map.get(YamlValue::String(key.to_string()))?;
    Some(match v {
        YamlValue::String(s) => s.clone(),
        other => serde_yaml::to_string(other).unwrap_or_default().trim().to_string(),
    })
}
