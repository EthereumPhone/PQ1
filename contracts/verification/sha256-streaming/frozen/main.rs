use original_buffer_indexed_probe::observe_step;
mod reference;

fn main() {
    let initial = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
    let input: [u8; 192] = core::array::from_fn(|i| (i as u8).wrapping_mul(53).wrapping_add(19));
    let before = core::array::from_fn(|i| (i as u8).wrapping_mul(19).wrapping_add(7));
    let after = core::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(5));
    let sparse = cfg!(miri) || std::env::args().any(|x| x == "--sparse");
    let probe_only = std::env::args().any(|x| x == "--probe-only");
    let mut cases = 0usize;
    let mut probes = 0usize;
    for pos in 0..64 {
        if sparse && ![0, 1, 55, 56, 63].contains(&pos) { continue; }
        for len in 0..=192 {
            if sparse && ![0, 1, 63, 64, 65, 127, 128, 129, 191, 192].contains(&len) { continue; }
            // Independent full-byte trace is the finite oracle. Mutant runs
            // exercise only the indexed observer so their rejection cannot be
            // credited to this older oracle instead of the new harness.
            let trace = if probe_only { None } else { Some(reference::full_trace(initial, pos, &input[..len])) };
            let total = pos + len;
            for probe in 0..total.max(1) {
                if sparse && ![0, pos.saturating_sub(1), pos, 63, 64, total / 64 * 64,
                               (total / 64 * 64).saturating_sub(1), total.saturating_sub(1)].contains(&probe) {
                    continue;
                }
                let observed = observe_step(initial, pos, &input[..len], probe, before, after);
                if let Some((bytes, emitted, residual, calls)) = trace {
                    assert_eq!(observed.emitted, emitted);
                    assert_eq!(observed.residual, residual);
                    assert_eq!(observed.calls, calls);
                    if total > 0 { assert_eq!(observed.byte, bytes[probe]); }
                }
                probes += 1;
            }
            cases += 1;
        }
    }
    println!("cases={cases} probes={probes} original-dependencies initialized-entry-only indexed-observer");
}
