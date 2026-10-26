import C10Probability.ByteStatefulCompile
import C10Probability.ByteObservedDriver

/-! Final observation of a stateful cutoff. A completed client supplies its
actual candidate; an unfinished client supplies malformed empty bytes and can
never gain a successful verification from cutoff exhaustion. Session failure,
caps and the complete table survive this finite observation. -/
namespace C10Probability
noncomputable section

def byteClientMap {R T : Type*} (finish : R → T) :
    {n : ℕ} → C10ByteClient R n → C10ByteClient T n
  | _, .done value => .done (finish value)
  | _, .hash key next => .hash key (fun reply => byteClientMap finish (next reply))
  | _, .sign req next => .sign req (fun reply => byteClientMap finish (next reply))

theorem byte_client_map_session {K R T : Type*} [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (finish : R → T) {n : ℕ} (client : C10ByteClient R n)
    (qr qs : ℕ) (ledger : C10SessionLedger) (table : Memo K Digest) :
    c10ByteSession encode cfg (byteClientMap finish client) qr qs ledger table =
      (c10ByteSession encode cfg client qr qs ledger table).map
        (fun out => (mapSessionValue finish out.1, out.2)) := by
  induction client generalizing qr qs ledger table with
  | done value => simp only [byteClientMap, c10ByteSession, PMF.pure_map, mapSessionValue]
  | hash key next ih =>
    cases qr <;> simp only [byteClientMap, c10ByteSession, ih, PMF.map_bind]
  | sign req next ih =>
    cases qs with
    | zero => simp only [byteClientMap, c10ByteSession, ih]
    | succ qs =>
      simp only [byteClientMap, c10ByteSession]
      split <;> simp only [ih, PMF.map_bind]

def byteOptionalForgery (value : Option C10ByteForgery) : C10ByteForgery := value.getD ([], [])

def c10ByteCutoffFinish {K : Type*} [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (out : C10SessionResult (Option C10ByteForgery) × Memo K Digest) :
    PMF (C10ByteGameOutput × Memo K Digest) :=
  let session := mapSessionValue byteOptionalForgery out.1
  (c10ByteFinal encode cfg session out.2).map (fun final => ((final.1, session), final.2))

theorem c10_byte_cutoff_finish_pending {K : Type*} [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (qr qs : ℕ) (ledger : C10SessionLedger) (table : Memo K Digest) :
    c10ByteCutoffFinish encode cfg (⟨none, ledger, qr, qs⟩, table) =
      PMF.pure ((false, ⟨([], []), ledger, qr, qs⟩), table) := by
  rw [c10ByteCutoffFinish, c10_byte_final_bad_length encode cfg _ table (by simp
    [mapSessionValue, byteOptionalForgery]), PMF.pure_map]
  rfl

theorem c10_byte_map_observed_driver {K : Type*} [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {n : ℕ} (client : C10ByteClient (Option C10ByteForgery) n)
    (qr qs : ℕ) (table : Memo K Digest) :
    c10ByteObservedDriver encode cfg (byteClientMap byteOptionalForgery client) qr qs table =
      (c10ByteSession encode cfg client qr qs emptySessionLedger table).bind
        (c10ByteCutoffFinish encode cfg) := by
  rw [c10ByteObservedDriver, byte_client_map_session, PMF.bind_map]
  rfl

def c10StatefulByteCutoffDriver {K S : Type*} [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (step : S → PMF (C10ByteAction S C10ByteForgery))
    (n : ℕ) (s : S) (qr qs : ℕ) (table : Memo K Digest) :
    PMF (C10ByteGameOutput × Memo K Digest) :=
  (c10StatefulByteCutoff encode cfg step n s qr qs emptySessionLedger table).bind
    (c10ByteCutoffFinish encode cfg)

theorem c10_stateful_byte_compiled_driver {K S : Type*} [DecidableEq K]
    (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (step : S → PMF (C10ByteAction S C10ByteForgery)) (n : ℕ) (s : S)
    (qr qs : ℕ) (table : Memo K Digest) :
    (c10StatefulByteCompile step n s).bind (fun client =>
        c10ByteObservedDriver encode cfg (byteClientMap byteOptionalForgery client) qr qs table) =
      c10StatefulByteCutoffDriver encode cfg step n s qr qs table := by
  simp only [c10_byte_map_observed_driver, c10StatefulByteCutoffDriver]
  rw [← PMF.bind_bind, c10_stateful_byte_compile_exact]

end
end C10Probability
