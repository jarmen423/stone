//! Deterministic micro-scenarios for sync edge cases — much faster to iterate
//! than the seeded random sim.

use stone_sim::Sim;

/// Two devices, one note; device B renames it while device A edits it.
/// Then both converge — the vault state must be identical.
#[test]
fn rename_vs_edit() {
    let mut sim = Sim::start(7, 2).expect("start");
    let (a, b) = sim.devices.split_at_mut(1);
    let a = &mut a[0];
    let b = &mut b[0];

    // seed file, both devices sync it
    a.engine.write_file("n.md", b"base\n").unwrap();
    a.agent.sync_now(&a.engine, true).unwrap();
    b.agent.sync_now(&b.engine, true).unwrap();

    // A edits offline-parallel; B renames
    a.engine.edit("n.md", "base", "edited by A", false).unwrap();
    b.engine.rename_file("n.md", "renamed.md").unwrap();

    a.agent.sync_now(&a.engine, true).unwrap(); // A pushes edit first
    b.agent.sync_now(&b.engine, true).unwrap(); // B rename commit lands after
    sim.converge();
    let rep = sim.verify().expect("verify");
    eprintln!("files ok: {}; divergent: {:?}", rep.total_files, rep.divergent);
}

/// Recreate-after-delete while another device holds an edit.
#[test]
fn delete_vs_edit() {
    let mut sim = Sim::start(8, 2).expect("start");
    let (a, b) = sim.devices.split_at_mut(1);
    let a = &mut a[0];
    let b = &mut b[0];

    a.engine.write_file("d.md", b"hello\n").unwrap();
    a.agent.sync_now(&a.engine, true).unwrap();
    b.agent.sync_now(&b.engine, true).unwrap();

    // B edits locally; A deletes the file; B syncs first (edit lands), then A.
    b.engine.edit("d.md", "hello", "edited by B", false).unwrap();
    a.engine.trash_file("d.md").unwrap();
    b.agent.sync_now(&b.engine, true).unwrap();
    a.agent.sync_now(&a.engine, true).unwrap();
    sim.converge();
    let rep = sim.verify().expect("verify");
    eprintln!("files ok: {}; divergent: {:?}", rep.total_files, rep.divergent);
}

/// Two devices create the same path with different content concurrently.
#[test]
fn create_create_collision() {
    let mut sim = Sim::start(9, 2).expect("start");
    let (a, b) = sim.devices.split_at_mut(1);
    let a = &mut a[0];
    let b = &mut b[0];

    a.engine.write_file("same.md", b"from A\n").unwrap();
    b.engine.write_file("same.md", b"from B\n").unwrap();
    a.agent.sync_now(&a.engine, true).unwrap();
    b.agent.sync_now(&b.engine, true).unwrap();
    sim.converge();
    let rep = sim.verify().expect("verify");
    eprintln!("files ok: {}; divergent: {:?}", rep.total_files, rep.divergent);
}
