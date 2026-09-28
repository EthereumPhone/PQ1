## Port notes

- **Time is milliseconds, never frames.** Every animation here is a pure function of elapsed ms; the panel samples it at {{val:tools.handoff.introspect.PANEL_FPS}} fps. Do not count frames on the device — keep the ms clock and let the frame rate fall where it falls.
- The numbers on this page are read from the running Python at build time. If the page and the code ever disagree, the code wins — then run `python3 -m tools.handoff --check`.
- No one-shot accent is shorter than {{tok:pq1.motion.VERDICT_ACCENT_MIN_MS}} — two panel frames — or the panel may never show it.
