import C10Probability.ByteSessionTypes

/-! Direct PMF semantics for the byte session, separately defined from the
structured-client translation. Refused requests consume no cap/cache; admitted
exhaustion consumes one sign cap and absorbs subsequent signing requests. -/
namespace C10Probability
noncomputable section

variable {K R S : Type*}

def c10SignBytes [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (req : C10SignRequest) (table : Memo K Digest) : PMF (Option ByteKey × Memo K Digest) :=
  (c10Sign encode table req.random req.message cfg.seed cfg.root req.shuffle
    cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound).map (fun reply => (byteSignReply reply.1, reply.2))

def c10ByteSession [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig) :
    {fuel : ℕ} → C10ByteClient R fuel → ℕ → ℕ → C10SessionLedger → Memo K Digest →
      PMF (C10SessionResult R × Memo K Digest)
  | _, .done value, qr, qs, ledger, table => PMF.pure (⟨value, ledger, qr, qs⟩, table)
  | _, .hash _ next, 0, qs, ledger, table => c10ByteSession encode cfg (next 0) 0 qs ledger table
  | _, .hash key next, qr + 1, qs, ledger, table =>
      (memoQuery digestDraw table (encode (.inl key))).bind
        (fun reply => c10ByteSession encode cfg (next reply.1) qr qs ledger reply.2)
  | _, .sign _ next, qr, 0, ledger, table =>
      c10ByteSession encode cfg (next none) qr 0 ledger table
  | _, .sign req next, qr, qs + 1, ledger, table =>
      if sessionAdmits ledger req then
        (c10SignBytes encode cfg req table).bind
          (fun reply => c10ByteSession encode cfg (next reply.1) qr qs
            (byteAfterSign ledger req.message reply.1) reply.2)
      else c10ByteSession encode cfg (next none) qr (qs + 1) ledger table

theorem c10_sign_bytes_width [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (req : C10SignRequest) (table : Memo K Digest)
    (bytes : ByteKey) (after : Memo K Digest)
    (supported : (some bytes, after) ∈ (c10SignBytes encode cfg req table).support) :
    bytes.length = 4008 := by
  rw [c10SignBytes, PMF.mem_support_map_iff] at supported
  obtain ⟨reply, _, equal⟩ := supported
  exact byte_sign_reply_width reply.1 bytes (congrArg Prod.fst equal)

theorem c10_byte_session_refinement [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (finish : R → S) {fuel : ℕ} (client : C10ByteClient R fuel)
    (qr qs : ℕ) (ledger : C10SessionLedger) (table : Memo K Digest) :
    c10Session encode cfg (byteClientToStructured finish client) qr qs ledger table =
      (c10ByteSession encode cfg client qr qs ledger table).map
        (fun out => (mapSessionValue finish out.1, out.2)) := by
  induction client generalizing qr qs ledger table with
  | done value =>
      simp only [byteClientToStructured, c10Session, c10ByteSession, PMF.pure_map, mapSessionValue]
  | hash key next ih =>
      cases qr with
      | zero => simp only [byteClientToStructured, c10Session, c10ByteSession, ih]
      | succ qr =>
          simp only [byteClientToStructured, c10Session, c10ByteSession, PMF.map_bind]
          apply pmf_bind_support_congr
          intro reply _
          exact ih reply.1 qr qs ledger reply.2
  | sign req next ih =>
      cases qs with
      | zero => simp only [byteClientToStructured, c10Session, c10ByteSession, byte_sign_reply_none, ih]
      | succ qs =>
          cases admitted : sessionAdmits ledger req with
          | false =>
              simp only [byteClientToStructured, c10Session, c10ByteSession, admitted,
                Bool.false_eq_true, ↓reduceIte, byte_sign_reply_none, ih]
          | true =>
              simp only [byteClientToStructured, c10Session, c10ByteSession, admitted,
                ↓reduceIte, c10SignBytes, PMF.bind_map, Function.comp_def, PMF.map_bind]
              apply pmf_bind_support_congr
              intro reply supported
              rw [byte_after_sign_eq ledger req.message reply.1
                (c10_sign_signature_shape encode table req.random req.message cfg.seed cfg.root req.shuffle
                  cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound reply supported)]
              exact ih (byteSignReply reply.1) qr qs _ reply.2

end
end C10Probability
