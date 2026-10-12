COMMENT_ON: 239
---
**Status check (2026-10-12): the on-silicon validation this issue asks for appears to be recorded. Not closing; please confirm.**

`docs/security/red-teaming.md:508-509` at master `0feea78a`: "Silicon-validated 2026-05-20 (`make gtzc-enforcement-hw` PASSED 7/7; USB still enumerates as `1209:7051`)". That is the first checkbox. The second (TAMP in GTZC2) is tracked in #81.

Note that the same document lists a re-run on the EVT unit as still to do (`docs/security/red-teaming.md:512`), so the receipt is for the dev kit, not for pq1 silicon. See also #70.
