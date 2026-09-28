//! Multi-device sync simulation over a real stone-server.
//! Runs several seeds; each run drives a seeded op schedule then asserts
//! convergence + zero lost edits.
//!
//! Divergence rule: `verify()` hard-fails on differing path sets, differing
//! content multisets (a lost edit), or pending entries left. It returns
//! `divergent` paths for reporting only — a true same-region conflict makes
//! the merged file differ per device while the losing side survives as a
//! ` (conflict …)` copy, which the multiset check still sees.
//!
//! These are plain `#[test]`s on purpose: SyncAgent calls are reqwest-
//! blocking and must not run inside a tokio runtime context.

use stone_sim::{Sim, SimReport};

fn run_seed(seed: u64, devices: usize, steps: usize, notes: usize) -> SimReport {
    let mut sim = Sim::start(seed, devices).expect("sim start");
    for _ in 0..steps {
        sim.step(notes);
    }
    sim.converge();
    sim.verify().expect("verify")
}

#[test]
fn sim_three_devices_converge() {
    for seed in 1..=3u64 {
        let rep = run_seed(seed, 3, 160, 6);
        assert!(rep.total_files > 0);
        eprintln!(
            "seed {seed}: {} files, {} divergent paths (conflict copies preserve remote)",
            rep.total_files,
            rep.divergent.len()
        );
    }
}

#[test]
fn sim_offline_windows() {
    for seed in 11..=12u64 {
        let rep = run_seed(seed, 4, 220, 8);
        eprintln!(
            "seed {seed}: {} files, {} divergent paths",
            rep.total_files,
            rep.divergent.len()
        );
    }
}
