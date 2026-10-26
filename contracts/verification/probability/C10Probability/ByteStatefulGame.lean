import C10Probability.ByteStatefulReturn
import C10Probability.ByteObservedGame

/-! Actual key generation followed by a stateful byte client. The compiler
samples continuations for all fixed-width public keys before key generation;
the keygen support theorem justifies selecting the actual public key. Neither
the client's initialization nor its transition function receives the cache. -/
namespace C10Probability
noncomputable section

abbrev C10StatefulByteAdversary (S : Type*) := ByteKey → ByteKey → S
abbrev C10PublicKeyFields := (Fin 32 → Fin 256) × (Fin 32 → Fin 256)

def bytePublicRead (bytes : ByteKey) : Fin 32 → Fin 256 := fun i => bytes[i.val]!

theorem byte_public_read_roundtrip (bytes : ByteKey) (width : bytes.length = 32) :
    List.ofFn (bytePublicRead bytes) = bytes := by
  change codecSlice 32 bytes 0 = bytes
  rw [codec_slice_eq_take _ _ _ (by omega)]
  simp [← width]

def c10StatefulByteAdversaryCompile {S : Type*}
    (step : S → PMF (C10ByteAction S C10ByteForgery)) (n : ℕ)
    (adversary : C10StatefulByteAdversary S) : PMF (C10ByteAdversary n) :=
  (pmfFamily (fun fields : C10PublicKeyFields =>
    (c10StatefulByteCompile step n (adversary (List.ofFn fields.1) (List.ofFn fields.2))).map
      (byteClientMap byteOptionalForgery))).map
        (fun clients seed root => clients (bytePublicRead seed, bytePublicRead root))

theorem c10_stateful_byte_adversary_at {S : Type*}
    (step : S → PMF (C10ByteAction S C10ByteForgery)) (n : ℕ)
    (adversary : C10StatefulByteAdversary S) (seed root : ByteKey)
    (seedWidth : seed.length = 32) (rootWidth : root.length = 32) :
    (c10StatefulByteAdversaryCompile step n adversary).map (fun client => client seed root) =
      (c10StatefulByteCompile step n (adversary seed root)).map
        (byteClientMap byteOptionalForgery) := by
  simp only [c10StatefulByteAdversaryCompile, PMF.map_comp, Function.comp_def,
    pmf_family_marginal, byte_public_read_roundtrip seed seedWidth,
    byte_public_read_roundtrip root rootWidth]

def c10StatefulByteCutoffGame {K S : Type*} [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest)
    (step : S → PMF (C10ByteAction S C10ByteForgery)) (n : ℕ)
    (adversary : C10StatefulByteAdversary S) (qr qs : ℕ) (table : Memo K Digest) :
    PMF (C10ByteGameOutput × Memo K Digest) :=
  (c10Keygen encode table publicSeed).bind (fun key =>
    c10StatefulByteCutoffDriver encode (sessionConfigAt cfg key.1) step n
      (adversary key.1.1 key.1.2) qr qs key.2)

theorem c10_stateful_byte_compiled_game {K S : Type*} [DecidableEq K]
    (encode : WotsQuery → K) (cfg : C10SessionConfig) (publicSeed : Digest)
    (step : S → PMF (C10ByteAction S C10ByteForgery)) (n : ℕ)
    (adversary : C10StatefulByteAdversary S) (qr qs : ℕ) (table : Memo K Digest) :
    (c10StatefulByteAdversaryCompile step n adversary).bind (fun client =>
        c10ByteObservedGame encode cfg publicSeed client qr qs table) =
      c10StatefulByteCutoffGame encode cfg publicSeed step n adversary qr qs table := by
  simp only [c10ByteObservedGame, c10StatefulByteCutoffGame]
  rw [PMF.bind_comm]
  apply pmf_bind_support_congr
  intro key supported
  obtain ⟨seedWidth, rootWidth⟩ := c10_keygen_widths encode table publicSeed key supported
  calc
    _ = ((c10StatefulByteAdversaryCompile step n adversary).map
        (fun client => client key.1.1 key.1.2)).bind
          (fun client => c10ByteObservedDriver encode (sessionConfigAt cfg key.1) client qr qs key.2) :=
      (PMF.bind_map _ _ _).symm
    _ = _ := by
      rw [c10_stateful_byte_adversary_at step n adversary _ _ seedWidth rootWidth,
        PMF.bind_map]
      exact c10_stateful_byte_compiled_driver encode (sessionConfigAt cfg key.1) step n
        (adversary key.1.1 key.1.2) qr qs key.2

end
end C10Probability
