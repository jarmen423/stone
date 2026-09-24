//! Minimal Obsidian-compatible template rendering for `stone new --template`.
//! Supported: {{date}}, {{time}}, {{title}} — plus {{date:FORMAT}} /
//! {{time:FORMAT}} using chrono strftime.

pub fn render(template: &str) -> String {
    render_with_title(template, "")
}

pub fn render_with_title(template: &str, title: &str) -> String {
    let now = chrono::Local::now();
    let mut out = template.to_string();
    // {{title}}
    out = out.replace("{{title}}", title);
    // {{date}} and {{date:FMT}}
    for (var, default_fmt) in [("date", "%Y-%m-%d"), ("time", "%H:%M")] {
        // find {{var:...}} occurrences
        loop {
            let pat = format!("{{{{{var}:");
            let Some(start) = out.find(&pat) else { break };
            let Some(end) = out[start..].find("}}") else { break };
            let fmt = &out[start + pat.len()..start + end];
            let rendered = now.format(fmt).to_string();
            out.replace_range(start..start + end + 2, &rendered);
        }
        out = out.replace(&format!("{{{{{var}}}}}"), &now.format(default_fmt).to_string());
    }
    out
}
