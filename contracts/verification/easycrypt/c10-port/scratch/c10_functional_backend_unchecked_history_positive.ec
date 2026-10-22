require import AllCore List FMap C10RawOracle C10FixedBackend.
lemma checked f h x0 c :
  hoare[FixedBackend.hash :
    FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ x = x0 /\ FixedBackend.calls = c ==>
    res = f x0 /\ FixedBackend.fn = f /\
    FixedBackend.history = remember h x0 (f x0) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c + 1].
proof. exact (fixed_hash f h x0 c). qed.
