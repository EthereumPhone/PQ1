import C10Probability.ByteStatefulSession

/-! Exact compilation of a stateful finite cutoff into a PMF of the existing
fuel-indexed byte clients. Random continuations are sampled independently of
the oracle. The signature branch uses the existing exact 4008-byte codec only
on supported replies. No success or freshness premise is required. -/
namespace C10Probability
noncomputable section

theorem byte_family_eval {K A R : Type*} [Fintype A] [DecidableEq K]
    (encode : WotsQuery → K) (cfg : C10SessionConfig) {n : ℕ}
    (p : A → PMF (C10ByteClient R n)) (a : A) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo K Digest) :
    (pmfFamily p).bind (fun values => c10ByteSession encode cfg (values a) qr qs ledger table) =
      (p a).bind (fun client => c10ByteSession encode cfg client qr qs ledger table) := by
  exact pmf_family_bind p a (fun client => c10ByteSession encode cfg client qr qs ledger table)

def c10StatefulByteCompile {S R : Type*} (step : S → PMF (C10ByteAction S R)) :
    (n : ℕ) → S → PMF (C10ByteClient (Option R) n)
  | 0, _ => PMF.pure (.done none)
  | n + 1, s => (step s).bind fun action => match action with
    | .done value => PMF.pure (.done (some value))
    | .tick next => (c10StatefulByteCompile step n next).map byteClientPad
    | .hash key next => (pmfFamily (fun reply => c10StatefulByteCompile step n (next reply))).map
        (fun continuations => .hash key continuations)
    | .sign req next =>
        (pmfFamily (fun reply : Option WireSignature =>
          c10StatefulByteCompile step n (next (reply.map wireEncode)))).map
            (fun continuations => .sign req (fun reply => continuations (reply.map wireDecode)))

theorem c10_stateful_byte_compile_exact {K S R : Type*} [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (step : S → PMF (C10ByteAction S R)) (n : ℕ) (s : S)
    (qr qs : ℕ) (ledger : C10SessionLedger) (table : Memo K Digest) :
    (c10StatefulByteCompile step n s).bind
        (fun client => c10ByteSession encode cfg client qr qs ledger table) =
      c10StatefulByteCutoff encode cfg step n s qr qs ledger table := by
  induction n generalizing s qr qs ledger table with
  | zero => simp only [c10StatefulByteCompile, PMF.pure_bind, c10ByteSession, c10StatefulByteCutoff]
  | succ n ih =>
    simp only [c10StatefulByteCompile, PMF.bind_bind, c10StatefulByteCutoff]
    congr 1
    funext action
    cases action with
    | done value => simp only [PMF.pure_bind, c10ByteSession]
    | tick next =>
      simpa only [PMF.bind_map, Function.comp_def, byte_client_pad_exact] using
        ih next qr qs ledger table
    | hash key next =>
      cases qr with
      | zero => simp only [PMF.bind_map, Function.comp_def, c10ByteSession, byte_family_eval, ih]
      | succ qr =>
        simp only [PMF.bind_map, Function.comp_def, c10ByteSession]
        rw [PMF.bind_comm]
        congr 1
        funext reply
        rw [byte_family_eval, ih]
    | sign req next =>
      cases qs with
      | zero => simp only [PMF.bind_map, Function.comp_def, c10ByteSession,
          Option.map_none, byte_family_eval, ih]
      | succ qs =>
        simp only [PMF.bind_map, Function.comp_def, c10ByteSession]
        split
        next admitted =>
          rw [PMF.bind_comm]
          apply pmf_bind_support_congr
          intro reply supported
          rw [byte_family_eval, ih]
          have exactReply : (reply.1.map wireDecode).map wireEncode = reply.1 := by
            cases h : reply.1 with
            | none => rfl
            | some bytes =>
              simp only [Option.map_some, Option.some.injEq]
              apply wire_encode_decode
              apply c10_sign_bytes_width encode cfg req table bytes reply.2
              simpa only [← h] using supported
          rw [exactReply]
        next refused =>
          simp only [Option.map_none, byte_family_eval, ih]

end
end C10Probability
