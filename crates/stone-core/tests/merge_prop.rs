//! Property tests for the merge engine.
//!
//! The merge is token-level diff3: invariants that must hold for ANY inputs:
//!  - merging identical sides returns that side, zero conflicts;
//!  - merging base with itself returns the other side verbatim;
//!  - disjoint-region edits merge cleanly with both present;
//!  - output is never empty when both inputs are non-empty;
//!  - determinism: same (base, ours, theirs) → same output.

use proptest::prelude::*;
use stone_core::merge::{diff3_merge, merge_file, MergeOutcome};

fn merged_of(out: &MergeOutcome) -> Vec<u8> {
    match out {
        MergeOutcome::Clean(b) => b.clone(),
        MergeOutcome::Conflicted { merged, .. } => merged.clone(),
    }
}

fn line_strategy() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec("[a-z]{1,6}", 0..30)
}

proptest! {
    #[test]
    fn identical_sides_merge_cleanly(base in line_strategy(), side in line_strategy()) {
        let b = base.join("\n");
        let s = side.join("\n");
        let m = diff3_merge(&b, &s, &s);
        prop_assert_eq!(m.conflicts, 0);
        prop_assert_eq!(m.merged, s);
    }

    #[test]
    fn base_unchanged_returns_other(base in line_strategy(), other in line_strategy()) {
        let b = base.join("\n");
        let o = other.join("\n");
        let m = diff3_merge(&b, &b, &o);
        prop_assert_eq!(m.merged.clone(), o.clone());
        let m2 = diff3_merge(&b, &o, &b);
        prop_assert_eq!(m2.merged, o);
    }

    #[test]
    fn deterministic(base in line_strategy(), a in line_strategy(), c in line_strategy()) {
        let (b, x, y) = (base.join("\n"), a.join("\n"), c.join("\n"));
        let m1 = diff3_merge(&b, &x, &y);
        let m2 = diff3_merge(&b, &x, &y);
        prop_assert_eq!(m1.merged, m2.merged);
        prop_assert_eq!(m1.conflicts, m2.conflicts);
    }

    #[test]
    fn merge_file_idempotent_on_equal(content in "[a-z \n]{0,200}") {
        let out = merge_file("note.md", content.as_bytes(), content.as_bytes(), content.as_bytes());
        prop_assert!(!out.had_conflict());
        prop_assert_eq!(merged_of(&out), content.into_bytes());
    }
}

#[test]
fn disjoint_edits_merge_both_sides() {
    let base = "one\ntwo\nthree\nfour\nfive\n";
    let ours = "ONE\ntwo\nthree\nfour\nfive\n"; // first line
    let theirs = "one\ntwo\nthree\nfour\nFIVE\n"; // last line
    let m = diff3_merge(base, ours, theirs);
    assert_eq!(m.conflicts, 0, "disjoint edits must not conflict: {}", m.merged);
    assert!(m.merged.contains("ONE"), "merged lost ours: {}", m.merged);
    assert!(m.merged.contains("FIVE"), "merged lost theirs: {}", m.merged);
}

#[test]
fn same_region_conflict_keeps_ours() {
    let base = "the quick fox\n";
    let ours = "the slow fox\n";
    let theirs = "the fast fox\n";
    let m = diff3_merge(base, ours, theirs);
    assert_eq!(m.conflicts, 1);
    assert!(m.merged.contains("slow"), "local-wins rule broken: {}", m.merged);
}
