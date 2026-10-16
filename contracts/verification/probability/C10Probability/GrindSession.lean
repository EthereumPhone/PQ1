import C10Probability.GrindInterface
import C10Probability.PreludeTransfer

/-! An adaptive prelude, the existing FORS grinder and an adaptive continuation.
The selected randomizer and full digest remain available to the continuation.
The ideal private oracle is memoized: this is not an independent-R experiment. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {A R : Type*}

def grindSessionProgram {a b : ℕ}
    (before : QueryProgram (Sum ByteKey ByteKey) Digest A a) (request : A → GrindRequest)
    (after : A → Option (ℕ × Randomizer × Digest) → QueryProgram (Sum ByteKey ByteKey) Digest R b)
    (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) :
    QueryProgram (Sum ByteKey ByteKey) Digest R ((b + 2 * n) + a) :=
  bindProgram before fun prior =>
    bindProgram (privateRandomizerProgram (request prior).random (request prior).message
      (request prior).seed (request prior).root n hb) (after prior)

def sharedGrindSession {a b : ℕ}
    (client : PMF (QueryProgram (Sum ByteKey ByteKey) Digest A a)) (request : A → GrindRequest)
    (after : A → Option (ℕ × Randomizer × Digest) → QueryProgram (Sum ByteKey ByteKey) Digest R b)
    (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) : PMF R :=
  digestDraw.bind fun secret => client.bind fun before =>
    (evalProgram digestDraw (mapProgram (privateKey prefixedPrivateInput secret) before)
      (fun _ => none)).bind fun prior =>
        (sharedRandomizerSearch prior.2 (secretBytes secret) (request prior.1).random
          (request prior.1).message (request prior.1).seed (request prior.1).root n hb).bind
          fun out => (evalProgram digestDraw
            (mapProgram (privateKey prefixedPrivateInput secret) (after prior.1 out.1)) out.2).map Prod.fst

def independentGrindSession {a b : ℕ}
    (client : PMF (QueryProgram (Sum ByteKey ByteKey) Digest A a)) (request : A → GrindRequest)
    (after : A → Option (ℕ × Randomizer × Digest) → QueryProgram (Sum ByteKey ByteKey) Digest R b)
    (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) : PMF R :=
  client.bind fun before =>
    (evalProgram digestDraw before (fun _ => none)).bind fun prior =>
      (privateRandomizerSearch prior.2 (request prior.1).random (request prior.1).message
        (request prior.1).seed (request prior.1).root n hb).bind fun out =>
          (evalProgram digestDraw (after prior.1 out.1) out.2).map Prod.fst

theorem grindSessionProgram_shared {a b : ℕ}
    (before : QueryProgram (Sum ByteKey ByteKey) Digest A a) (request : A → GrindRequest)
    (after : A → Option (ℕ × Randomizer × Digest) → QueryProgram (Sum ByteKey ByteKey) Digest R b)
    (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) (secret : Digest) (table : Memo ByteKey Digest) :
    evalProgram digestDraw
      (mapProgram (privateKey prefixedPrivateInput secret)
        (grindSessionProgram before request after n hb)) table =
      (evalProgram digestDraw (mapProgram (privateKey prefixedPrivateInput secret) before) table).bind
        (fun prior => (sharedRandomizerSearch prior.2 (secretBytes secret) (request prior.1).random
          (request prior.1).message (request prior.1).seed (request prior.1).root n hb).bind
          (fun out => evalProgram digestDraw
            (mapProgram (privateKey prefixedPrivateInput secret) (after prior.1 out.1)) out.2)) := by
  unfold grindSessionProgram
  rw [mapProgram_bind, evalProgram_bind]
  congr 1
  funext prior
  rw [mapProgram_bind, evalProgram_bind, privateRandomizerProgram_shared]

theorem grindSessionProgram_independent {a b : ℕ}
    (before : QueryProgram (Sum ByteKey ByteKey) Digest A a) (request : A → GrindRequest)
    (after : A → Option (ℕ × Randomizer × Digest) → QueryProgram (Sum ByteKey ByteKey) Digest R b)
    (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) (table : Memo (Sum ByteKey ByteKey) Digest) :
    evalProgram digestDraw (grindSessionProgram before request after n hb) table =
      (evalProgram digestDraw before table).bind fun prior =>
        (privateRandomizerSearch prior.2 (request prior.1).random (request prior.1).message
          (request prior.1).seed (request prior.1).root n hb).bind fun out =>
            evalProgram digestDraw (after prior.1 out.1) out.2 := by
  unfold grindSessionProgram
  rw [evalProgram_bind]
  congr 1
  funext prior
  rw [evalProgram_bind, privateRandomizerProgram_independent]

theorem grindSessionProgram_budget {a b : ℕ}
    (before : QueryProgram (Sum ByteKey ByteKey) Digest A a) (request : A → GrindRequest)
    (after : A → Option (ℕ × Randomizer × Digest) → QueryProgram (Sum ByteKey ByteKey) Digest R b)
    (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) (q r : ℕ)
    (first : PublicBudget before q) (later : ∀ prior out, PublicBudget (after prior out) r) :
    PublicBudget (grindSessionProgram before request after n hb) (q + n + r) := by
  unfold grindSessionProgram
  simpa only [Nat.add_assoc] using publicBudget_bind before _ q (n + r) first
    (fun prior => publicBudget_bind _ (after prior) n r
      (privateRandomizerProgram_budget _ _ _ _ n hb) (later prior))

theorem sharedGrindSession_client {a b : ℕ}
    (client : PMF (QueryProgram (Sum ByteKey ByteKey) Digest A a)) (request : A → GrindRequest)
    (after : A → Option (ℕ × Randomizer × Digest) → QueryProgram (Sum ByteKey ByteKey) Digest R b)
    (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) :
    privateShared digestDraw digestDraw prefixedPrivateInput
      (client.map (fun before => grindSessionProgram before request after n hb)) =
      sharedGrindSession client request after n hb := by
  simp only [privateShared, privateSharedAt, PMF.bind_map, Function.comp_def,
    grindSessionProgram_shared, PMF.map_bind, sharedGrindSession]

theorem independentGrindSession_client {a b : ℕ}
    (client : PMF (QueryProgram (Sum ByteKey ByteKey) Digest A a)) (request : A → GrindRequest)
    (after : A → Option (ℕ × Randomizer × Digest) → QueryProgram (Sum ByteKey ByteKey) Digest R b)
    (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) :
    privateIndependent digestDraw
      (client.map (fun before => grindSessionProgram before request after n hb)) =
      independentGrindSession client request after n hb := by
  simp only [privateIndependent, randomizedProgram, PMF.bind_map, Function.comp_def,
    grindSessionProgram_independent, PMF.map_bind, independentGrindSession]

theorem grindSessionClient_budget {a b : ℕ}
    (client : PMF (QueryProgram (Sum ByteKey ByteKey) Digest A a)) (request : A → GrindRequest)
    (after : A → Option (ℕ × Randomizer × Digest) → QueryProgram (Sum ByteKey ByteKey) Digest R b)
    (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) (q r : ℕ)
    (first : ∀ before ∈ client.support, PublicBudget before q)
    (later : ∀ prior out, PublicBudget (after prior out) r) :
    ∀ program ∈ (client.map (fun before => grindSessionProgram before request after n hb)).support,
      PublicBudget program (q + n + r) := by
  intro program hp
  rw [PMF.mem_support_map_iff] at hp
  obtain ⟨before, hbefore, rfl⟩ := hp
  exact grindSessionProgram_budget before request after n hb q r (first before hbefore) later

theorem grindSession_event_bounds {a b : ℕ}
    (client : PMF (QueryProgram (Sum ByteKey ByteKey) Digest A a)) (request : A → GrindRequest)
    (after : A → Option (ℕ × Randomizer × Digest) → QueryProgram (Sum ByteKey ByteKey) Digest R b)
    (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) (q r : ℕ)
    (first : ∀ before ∈ client.support, PublicBudget before q)
    (later : ∀ prior out, PublicBudget (after prior out) r) (event : Set R) :
    (sharedGrindSession client request after n hb).toOuterMeasure event ≤
      (independentGrindSession client request after n hb).toOuterMeasure event +
        ((q + n + r : ℕ) : ℝ≥0∞) / 2 ^ 256 ∧
    (independentGrindSession client request after n hb).toOuterMeasure event ≤
      (sharedGrindSession client request after n hb).toOuterMeasure event +
        ((q + n + r : ℕ) : ℝ≥0∞) / 2 ^ 256 := by
  simpa only [sharedGrindSession_client, independentGrindSession_client] using
    private_secret_event_bounds
      (client.map (fun before => grindSessionProgram before request after n hb)) (q + n + r)
      (grindSessionClient_budget client request after n hb q r first later) event

theorem grindSession_event_error_real {a b : ℕ}
    (client : PMF (QueryProgram (Sum ByteKey ByteKey) Digest A a)) (request : A → GrindRequest)
    (after : A → Option (ℕ × Randomizer × Digest) → QueryProgram (Sum ByteKey ByteKey) Digest R b)
    (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) (q r : ℕ)
    (first : ∀ before ∈ client.support, PublicBudget before q)
    (later : ∀ prior out, PublicBudget (after prior out) r) (event : Set R) :
    |((sharedGrindSession client request after n hb).toOuterMeasure event).toReal -
      ((independentGrindSession client request after n hb).toOuterMeasure event).toReal| ≤
        ((q + n + r : ℕ) : ℝ) / 2 ^ 256 := by
  simpa only [sharedGrindSession_client, independentGrindSession_client] using
    private_secret_event_error_real
      (client.map (fun before => grindSessionProgram before request after n hb)) (q + n + r)
      (grindSessionClient_budget client request after n hb q r first later) event

theorem grindSession_signing_error {a b : ℕ}
    (client : PMF (QueryProgram (Sum ByteKey ByteKey) Digest A a)) (request : A → GrindRequest)
    (after : A → Option (ℕ × Randomizer × Digest) → QueryProgram (Sum ByteKey ByteKey) Digest R b)
    (q r : ℕ) (first : ∀ before ∈ client.support, PublicBudget before q)
    (later : ∀ prior out, PublicBudget (after prior out) r) (event : Set R) :
    |((sharedGrindSession client request after signingBudget signing_counter_fits).toOuterMeasure event).toReal -
      ((independentGrindSession client request after signingBudget signing_counter_fits).toOuterMeasure event).toReal| ≤
        ((q + signingBudget + r : ℕ) : ℝ) / 2 ^ 256 := by
  exact grindSession_event_error_real client request after signingBudget signing_counter_fits
    q r first later event

end
end C10Probability
