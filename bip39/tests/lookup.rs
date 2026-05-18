//! Positive + negative coverage of `lookup_word_exact` and `lookup_prefix` —
//! the surface the recovery-wizard UX touches every time a user types a
//! mnemonic word. A silent acceptance of a non-wordlist string here would
//! propagate into `from_words` and brick recovery.

use sphincs_tz_bip39::{lookup_prefix, lookup_word_exact, PrefixLookup, WORDLIST};

// ---------------------------------------------------------------------------
// `lookup_word_exact`
// ---------------------------------------------------------------------------

#[test]
fn positive_lookup_word_exact_first_and_last_word() {
    assert_eq!(lookup_word_exact("abandon"), Some(0));
    assert_eq!(lookup_word_exact("zoo"), Some(2047));
}

#[test]
fn positive_lookup_word_exact_is_case_insensitive_ascii() {
    assert_eq!(lookup_word_exact("ABANDON"), Some(0));
    assert_eq!(lookup_word_exact("AbAnDoN"), Some(0));
    assert_eq!(lookup_word_exact("Abandon"), Some(0));
    assert_eq!(lookup_word_exact("Zoo"), Some(2047));
    assert_eq!(lookup_word_exact("ZOO"), Some(2047));
}

#[test]
fn positive_lookup_word_exact_round_trips_every_wordlist_entry() {
    for (i, w) in WORDLIST.iter().enumerate() {
        assert_eq!(
            lookup_word_exact(w),
            Some(i as u16),
            "wordlist entry {:?} at index {} must look up to that index",
            w,
            i,
        );
    }
}

#[test]
fn negative_lookup_word_exact_rejects_obvious_non_word() {
    assert_eq!(lookup_word_exact("notaword"), None);
    assert_eq!(lookup_word_exact("xyzzy"), None);
}

#[test]
fn negative_lookup_word_exact_rejects_empty_string() {
    assert_eq!(lookup_word_exact(""), None);
}

#[test]
fn negative_lookup_word_exact_rejects_overlong_input() {
    // `MAX_WORD_LEN = 16` — anything longer must be rejected, not silently
    // truncated to a valid wordlist entry.
    let too_long = "a".repeat(17);
    assert_eq!(lookup_word_exact(&too_long), None);
    let way_too_long = "abandon".repeat(10);
    assert_eq!(lookup_word_exact(&way_too_long), None);
}

#[test]
fn negative_lookup_word_exact_rejects_trailing_whitespace() {
    assert_eq!(lookup_word_exact("abandon "), None);
    assert_eq!(lookup_word_exact("abandon\t"), None);
    assert_eq!(lookup_word_exact("abandon\n"), None);
}

#[test]
fn negative_lookup_word_exact_rejects_leading_whitespace() {
    assert_eq!(lookup_word_exact(" abandon"), None);
    assert_eq!(lookup_word_exact("\tabandon"), None);
}

#[test]
fn negative_lookup_word_exact_rejects_non_ascii() {
    // Cyrillic 'а' looks identical to 'a' but is a different code point. The
    // `to_ascii_lowercase` path must NOT smooth this over.
    assert_eq!(lookup_word_exact("аbandon"), None);
    assert_eq!(lookup_word_exact("abandön"), None);
    assert_eq!(lookup_word_exact("ABANDÖN"), None);
}

#[test]
fn negative_lookup_word_exact_rejects_digit_or_punct() {
    assert_eq!(lookup_word_exact("abandon!"), None);
    assert_eq!(lookup_word_exact("abandon1"), None);
    assert_eq!(lookup_word_exact("1abandon"), None);
}

// ---------------------------------------------------------------------------
// `lookup_prefix`
// ---------------------------------------------------------------------------

#[test]
fn positive_lookup_prefix_empty_returns_full_range() {
    assert_eq!(
        lookup_prefix(""),
        PrefixLookup::Multiple {
            start: 0,
            end: WORDLIST.len(),
        }
    );
}

#[test]
fn positive_lookup_prefix_unique_for_zoo() {
    // "zoo" is the last word and no later word starts with it.
    assert_eq!(lookup_prefix("zoo"), PrefixLookup::Unique(2047));
}

#[test]
fn positive_lookup_prefix_multiple_for_ab() {
    let r = lookup_prefix("ab");
    let PrefixLookup::Multiple { start, end } = r else {
        panic!("expected Multiple, got {r:?}");
    };
    assert!(end > start);
    for w in &WORDLIST[start..end] {
        assert!(w.starts_with("ab"), "{w:?} does not start with 'ab'");
    }
    // At least `abandon`, `ability`, `able`, `about`, `above`, ...
    assert!(end - start >= 5);
}

#[test]
fn positive_lookup_prefix_case_insensitive() {
    assert_eq!(lookup_prefix("ZOO"), PrefixLookup::Unique(2047));
    let r = lookup_prefix("AB");
    assert!(matches!(r, PrefixLookup::Multiple { .. }));
}

#[test]
fn negative_lookup_prefix_returns_none_for_unknown_prefix() {
    assert_eq!(lookup_prefix("xx"), PrefixLookup::None);
    assert_eq!(lookup_prefix("zz"), PrefixLookup::None);
    assert_eq!(lookup_prefix("qz"), PrefixLookup::None);
}

#[test]
fn negative_lookup_prefix_returns_none_for_overlong() {
    let too_long = "a".repeat(17);
    assert_eq!(lookup_prefix(&too_long), PrefixLookup::None);
}

#[test]
fn negative_lookup_prefix_returns_none_for_non_ascii() {
    // Non-ASCII bytes are not touched by `to_ascii_lowercase`, so they can't
    // match a lowercase-ASCII wordlist entry. `PrefixLookup::None` is the
    // only safe answer.
    assert_eq!(lookup_prefix("аbandon"), PrefixLookup::None); // cyrillic а
}

#[test]
fn negative_lookup_prefix_bounds_are_tight_for_every_letter() {
    // For every first-letter prefix, the returned range — Unique or
    // Multiple — must be tight: every entry inside starts with the prefix,
    // neither neighbour outside does.
    for c in b'a'..=b'z' {
        let buf = [c];
        let s = core::str::from_utf8(&buf).unwrap();
        match lookup_prefix(s) {
            PrefixLookup::Unique(i) => {
                assert!((i as usize) < WORDLIST.len());
                assert!(WORDLIST[i as usize].starts_with(s));
                // And no other word in the list starts with this letter.
                let count = WORDLIST.iter().filter(|w| w.starts_with(s)).count();
                assert_eq!(count, 1, "letter {s} matched Unique but {count} words start with it");
            }
            PrefixLookup::Multiple { start, end } => {
                assert!(start < end);
                assert!(end <= WORDLIST.len());
                for w in &WORDLIST[start..end] {
                    assert!(w.starts_with(s), "{w:?} doesn't start with {s:?}");
                }
                if start > 0 {
                    assert!(!WORDLIST[start - 1].starts_with(s));
                }
                if end < WORDLIST.len() {
                    assert!(!WORDLIST[end].starts_with(s));
                }
            }
            PrefixLookup::None => {
                let any = WORDLIST.iter().any(|w| w.starts_with(s));
                assert!(
                    !any,
                    "lookup_prefix({s:?}) returned None but at least one word starts with it"
                );
            }
        }
    }
}

#[test]
fn positive_lookup_prefix_includes_exact_word_in_range() {
    // For each wordlist entry, `lookup_prefix(w)` is either `Unique(i)` with
    // the right `i`, or `Multiple { start, end }` with `i ∈ [start, end)` —
    // because every word at least matches itself.
    for (i, w) in WORDLIST.iter().enumerate() {
        match lookup_prefix(w) {
            PrefixLookup::Unique(idx) => assert_eq!(idx as usize, i),
            PrefixLookup::Multiple { start, end } => {
                assert!(
                    (start..end).contains(&i),
                    "exact word {w:?} (idx {i}) not in returned range [{start},{end})"
                );
            }
            PrefixLookup::None => panic!("exact word {w:?} matched nothing"),
        }
    }
}
