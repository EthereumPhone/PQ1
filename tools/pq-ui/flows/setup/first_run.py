"""FIRST RUN — set up the device: PIN, duress PIN, the seed backed up and
checked (audit HS-09).

  SET UP PQ1? (the hold) -> SET PIN -> REPEAT PIN -> SET DURESS PIN ->
  REPEAT DURESS PIN -> WRITE DOWN 24 WORDS (intro) -> the 24 WORDS
  (3 pages) -> WORDS WRITTEN DOWN? (the hold) -> CHECK 3 -> CHECK 12 ->
  CHECK 22 -> SETUP COMPLETE (the default ending, success/)
                   -> --end failed: CHECK 22 answered wrong, WRONG SEED
                      PHRASE (cancel/; on the bench the check comes back)

On the bench (.venv/bin/python tools/panel/play_flow.py setup/first_run)
every step is typed live: a REPEAT that misses shows PIN MISMATCH and
returns to the SET it repeats; a duress PIN equal to the PIN shows DURESS
PIN MUST DIFFER and asks again; a wrong check word shows WRONG SEED
PHRASE and asks the same word again.

The PINs, the words and which words are checked are VARIABLE — the
user's and the device's; the module's are samples.

    python3 -m flows setup/first_run --end all
"""
from flows.setup import (DEFAULTS, backup_intro, check, repeat_duress,  # noqa: F401
                         repeat_pin, set_duress, set_pin, setup_complete,
                         words, written_ask)

# the seed — a sample of 24 words (the device's is the user's)
SEED = ["close", "agent", "own", "deputy", "grape", "though", "sail", "simple",
        "ribbon", "cactus", "noble", "violet", "ember", "lucky", "orbit", "pencil",
        "tundra", "mimic", "gravel", "spice", "fetch", "cabin", "motor", "dawn"]
CHECKS = (3, 12, 22)     # which words are checked — the device picks; a sample

BODY = [
    dict(id="SETUP", kind="hero", bottom="SET UP PQ1?", chev="lr", hint=True),
    set_pin(),
    repeat_pin(),
    set_duress(),
    repeat_duress(),
    backup_intro(len(SEED)),
    words(SEED),
    written_ask(),
    check(CHECKS[0], SEED),
    check(CHECKS[1], SEED),
]

ENDS = {
    "successful": check(CHECKS[2], SEED, match=setup_complete()),
    "failed": check(CHECKS[2], SEED, typed=1, state="failed",
                    match=setup_complete()),
}
DEFAULT_END = "successful"
SCREENS = BODY + [ENDS[DEFAULT_END]]
