import C10Probability.ByteSession
import C10Probability.PMFFiniteFamily

/-! A byte client with arbitrary private state and fresh PMF randomness at each
step. Internal ticks and refused calls count towards a finite approximation,
not towards the admitted raw/sign caps. No uniform termination bound is part
of the client type, and its transition function receives no oracle cache. -/
namespace C10Probability
noncomputable section

inductive C10ByteAction (S R : Type*) where
  | done (value : R)
  | tick (next : S)
  | hash (key : ByteKey) (next : Digest → S)
  | sign (req : C10SignRequest) (next : Option ByteKey → S)

def byteClientPad {R : Type*} : {n : ℕ} → C10ByteClient R n → C10ByteClient R (n + 1)
  | _, .done value => .done value
  | _, .hash key next => .hash key (fun reply => byteClientPad (next reply))
  | _, .sign req next => .sign req (fun reply => byteClientPad (next reply))

theorem byte_client_pad_exact {K R : Type*} [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {n : ℕ} (client : C10ByteClient R n)
    (qr qs : ℕ) (ledger : C10SessionLedger) (table : Memo K Digest) :
    c10ByteSession encode cfg (byteClientPad client) qr qs ledger table =
      c10ByteSession encode cfg client qr qs ledger table := by
  induction client generalizing qr qs ledger table with
  | done value => rfl
  | hash key next ih => cases qr <;> simp only [byteClientPad, c10ByteSession, ih]
  | sign req next ih =>
    cases qs with
    | zero => simp only [byteClientPad, c10ByteSession, ih]
    | succ qs =>
      simp only [byteClientPad, c10ByteSession]
      split <;> simp only [ih]

end
end C10Probability
