# Actual FORS forest composition

ActualForestConstruction calls actual RawForest.sign and RawForest.recover.
With probability one, recovery returns the compressed root produced during
that signing call. This covers the concrete software shuffle, all twelve
authentication paths, the thirteenth root-as-secret with no transmitted path,
and the final concatenation of thirteen padded roots.

The signer records an opening for each tree it visits. Oracle and component
calls preserve earlier openings. The actual shuffle covers the complete index
range, so the completed arrays retain all twelve paths. The final secret is
produced by the real RawFors.root call; its special leaf-hash entry is recorded
under tree 12 and then used in the actual compression input. Recovery replays
each retained path and both final hashes. Zero nodes remain allowed.

This is equality to the root produced during actual signing. It does not
identify an independently generated forest public root, establish an adaptive
forgery reduction or charge the probability of collisions. Those distinctions
remain explicit even though honest FORS path construction is separately
proved in the construction batch.

The certificate enrolls all eleven forest modules and nine semantic/scope
controls. Each proof body is checked through direct and default-CLI drivers.
The required full cold replay and bounded review bind the merge receipt to
the candidate identity.

The independent-table and manual-transcription boundaries remain: no Rust
extraction, concrete SHA-256 theorem, QROM, numerical end-to-end security bound
or hardware/production authority follows. Remaining adaptive
reduction work stays under #100/#295; the owner-triggered playbook pass #509
remains deferred.
