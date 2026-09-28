//! End-to-end core ops: init a vault, write notes, resolve links, mv with
//! backlink rewriting, search, frontmatter, daily notes.

use stone_core::config;
use stone_core::engine::Engine;
use stone_core::registry;

fn fresh_vault() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    config::init_vault(dir.path(), Some("test")).unwrap();
    let engine = Engine::open(dir.path()).unwrap();
    (dir, engine)
}

#[test]
fn write_cat_search() {
    let (_d, e) = fresh_vault();
    e.new_note("Alpha", Some("# Alpha\n\nhello stone\n"), None).unwrap();
    e.new_note("Beta", Some("links to [[Alpha]]\n"), None).unwrap();
    e.new_note("Plain/Gamma", Some("nothing\n"), None).unwrap();

    assert!(e.cat("Alpha").unwrap().contains("hello stone"));
    // resolve by basename and by path
    assert_eq!(e.resolve_note("Alpha").unwrap(), "Alpha.md");
    assert_eq!(e.resolve_note("Plain/Gamma").unwrap(), "Plain/Gamma.md");

    let hits = e.index().unwrap().search(
        &stone_core::index::parse_search_query("hello"),
        10,
    ).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].path, "Alpha.md");
}

#[test]
fn mv_rewrites_backlinks() {
    let (_d, e) = fresh_vault();
    e.new_note("Target", Some("# T\n"), None).unwrap();
    e.new_note("Ref", Some("see [[Target]] and [[Target|alias]]\n"), None)
        .unwrap();
    e.new_note("Other", Some("[[Target#sec]] plus [[missing]]\n"), None)
        .unwrap();

    let r = e.mv("Target", "Renamed", false).unwrap();
    assert_eq!(r.to, "Renamed.md");
    assert!(e.cat("Ref").unwrap().contains("[[Renamed]]"));
    assert!(e.cat("Ref").unwrap().contains("[[Renamed|alias]]"));
    assert!(e.cat("Other").unwrap().contains("[[Renamed#sec]]"));
    assert!(e.cat("Other").unwrap().contains("[[missing]]"));

    // dry run does not touch files
    let _ = e.new_note("T2", Some("x [[Renamed]]\n"), None).unwrap();
    let dry = e.mv("Renamed", "Again", true).unwrap();
    assert!(!dry.edits.is_empty());
    assert!(e.cat("T2").unwrap().contains("[[Renamed]]"));
}

#[test]
fn props_and_tasks() {
    let (_d, e) = fresh_vault();
    e.new_note("P", Some("# p\n- [ ] first\n- [x] done\n"), None).unwrap();
    e.prop_set("P", "status", "wip").unwrap();
    let c = e.cat("P").unwrap();
    assert!(c.contains("status: wip"));
    assert!(c.starts_with("---"));
    let tasks = e.index().unwrap().tasks(false).unwrap();
    assert_eq!(tasks.len(), 2);
    let open = e.index().unwrap().tasks(true).unwrap();
    assert_eq!(open.len(), 1);
}

#[test]
fn registry_json_envelope() {
    let (_d, e) = fresh_vault();
    e.new_note("N", Some("content here\n"), None).unwrap();
    let v = registry::invoke(&e, "cat", &serde_json::json!({"note": "N"})).unwrap();
    assert_eq!(v["content"].as_str().unwrap(), "content here\n");
    let err = registry::invoke(&e, "cat", &serde_json::json!({"note": "nope"})).unwrap_err();
    assert_eq!(err.code(), "not_found");
}

#[test]
fn trash_restore_roundtrip() {
    let (_d, e) = fresh_vault();
    e.new_note("Del", Some("bye\n"), None).unwrap();
    let trashed = e.trash_file("Del.md").unwrap();
    assert!(trashed.contains(".stone/trash"), "{trashed}");
    assert!(e.cat("Del").is_err());
    let restored = e.trash_restore(trashed.split('/').last().unwrap(), "Del.md").unwrap();
    assert_eq!(restored, "Del.md");
    assert_eq!(e.cat("Del").unwrap(), "bye\n");
}
