import C10Probability.PrefixGuess
import C10Probability.SharedRandomizer

/-! Exact full-width secret prefixes for the manually transcribed R_grind
input. A short byte string cannot name a complete 256-bit prefix. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def secretBytes (secret : Digest) : ByteKey := List.ofFn (bytesDigestEquiv.symm secret)

def decodeSecretPrefix (key : ByteKey) : Option Digest :=
  if h : 32 ≤ key.length then
    some (bytesDigestEquiv fun i => key[i.val]'(lt_of_lt_of_le i.isLt h))
  else none

theorem secret_bytes_length (secret : Digest) : (secretBytes secret).length = 32 := by
  simp [secretBytes]

theorem decodeSecretPrefix_short (key : ByteKey) (h : key.length < 32) :
    decodeSecretPrefix key = none := by
  simp [decodeSecretPrefix, Nat.not_le_of_lt h]

theorem decodeSecretPrefix_append (bytes : DigestBytes) (tail : ByteKey) :
    decodeSecretPrefix (List.ofFn bytes ++ tail) = some (bytesDigestEquiv bytes) := by
  have h : 32 ≤ (List.ofFn bytes ++ tail).length := by simp
  rw [decodeSecretPrefix, dif_pos h]
  apply congrArg (fun b : DigestBytes => some (bytesDigestEquiv b))
  funext i
  rw [List.getElem_append_left (by simpa only [List.length_ofFn] using i.isLt)]
  simp only [List.getElem_ofFn]

theorem decodeSecretPrefix_secret (secret : Digest) (tail : ByteKey) :
    decodeSecretPrefix (secretBytes secret ++ tail) = some secret := by
  rw [secretBytes, decodeSecretPrefix_append, digest_bytes_roundtrip]

theorem r_input_secret_prefix (secret : Digest) (random message : ByteKey) (nonce : Counter) :
    decodeSecretPrefix (rDerivationInput (secretBytes secret) random message nonce) =
      some secret := by
  simp only [rDerivationInput, counterKey, rInputStem, List.append_assoc]
  exact decodeSecretPrefix_secret secret _

theorem secret_prefix_first_byte :
    decodeSecretPrefix (1 :: List.replicate 31 0) =
      some ⟨2 ^ 248, by decide⟩ := by decide

theorem secret_prefix_last_byte :
    decodeSecretPrefix (List.replicate 31 0 ++ [1]) = some 1 := by decide

theorem secret_prefix_suffix_ignored (secret : Digest) (a b : ByteKey) :
    decodeSecretPrefix (secretBytes secret ++ a) =
      decodeSecretPrefix (secretBytes secret ++ b) := by
  simp [decodeSecretPrefix_secret]

variable {R : Type*}

theorem public_prelude_secret_bound {q : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R q)) :
    (((secretPrelude digestDraw digestDraw client (fun _ => none)).map
      (prefixHit decodeSecretPrefix)) true).toReal ≤ (q : ℝ) / (2 : ℝ) ^ 256 := by
  simpa only [digestDraw, Fintype.card_fin, Nat.cast_pow, Nat.cast_ofNat] using
    secretPrelude_prefix_bound_real decodeSecretPrefix digestDraw client (fun _ => none)

theorem public_prelude_r_fresh {q : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R q))
    (out : Digest × TraceOutput ByteKey Digest R)
    (ho : out ∈ (secretPrelude digestDraw digestDraw client (fun _ => none)).support)
    (hg : prefixHit decodeSecretPrefix out = false) (random message : ByteKey)
    (start n : ℕ) (hb : start + n ≤ 2 ^ 32) :
    ∀ key ∈ counterSchedule (rInputStem (secretBytes out.1) random message) start n hb,
      out.2.cache key = none := by
  intro key hk
  obtain ⟨i, rfl⟩ := List.mem_ofFn.mp hk
  exact prefixHit_false_fresh decodeSecretPrefix digestDraw client out
    (secretPrelude_support digestDraw digestDraw client (fun _ => none) out ho) hg _
      (r_input_secret_prefix out.1 random message _)

end
end C10Probability
