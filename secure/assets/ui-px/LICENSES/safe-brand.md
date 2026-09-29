# Safe logo mark (`../safe.a4`)

Third-party brand asset. The mark is derived from `tools/pq-ui/pq1/assets/safe.png`
(the design repo's copy of the Safe logo; sha256 in `../manifest.json`). It is
baked as an alpha mask of the dark glyph only — the green disc is drawn
procedurally on-device, matching the design's `components.token()`.

Production embedding requires an explicit owner sign-off against Safe's brand
guidelines (https://safe.global — brand assets page) recorded here, and
`"safe_logo_approved": true` in `../manifest.json`; `secure/build.rs` refuses to
embed the mark into a `mode-production` image while it is `false`.

Sign-off: **none yet** (bench/pilot use only).
