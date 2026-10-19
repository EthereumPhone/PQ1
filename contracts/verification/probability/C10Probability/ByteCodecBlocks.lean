import C10Probability.ByteCodec

/-! Compositional fixed-width codecs. Products concatenate fields; arrays keep
row-major occurrence order. These equations expose the concrete byte layout,
rather than relying on an abstract bijection alone. -/
namespace C10Probability
noncomputable section

def codecPairEquiv {α β : Type*} (m n : ℕ)
    (left : (Fin m → Fin 256) ≃ α) (right : (Fin n → Fin 256) ≃ β) :
    (Fin (m + n) → Fin 256) ≃ α × β where
  toFun bytes := (left (fun i => bytes (i.castAdd n)), right (fun i => bytes (i.natAdd m)))
  invFun pair := Fin.append (left.symm pair.1) (right.symm pair.2)
  left_inv bytes := by
    funext i
    refine Fin.addCases ?_ ?_ i
    · intro j
      simp
    · intro j
      simp
  right_inv pair := by
    apply Prod.ext <;> simp

theorem codec_pair_bytes {α β : Type*} (m n : ℕ)
    (left : (Fin m → Fin 256) ≃ α) (right : (Fin n → Fin 256) ≃ β)
    (a : α) (b : β) :
    codecBytes (m + n) (codecPairEquiv m n left right) (a, b) =
      codecBytes m left a ++ codecBytes n right b := by
  exact List.ofFn_fin_append _ _

theorem codec_pair_read {α β : Type*} (m n : ℕ)
    (left : (Fin m → Fin 256) ≃ α) (right : (Fin n → Fin 256) ≃ β)
    (bytes : ByteKey) (offset : ℕ) :
    codecRead (m + n) (codecPairEquiv m n left right) bytes offset =
      (codecRead m left bytes offset, codecRead n right bytes (offset + m)) := by
  simp only [codecRead, codecPairEquiv, Equiv.coe_fn_mk, Fin.val_castAdd,
    Fin.val_natAdd, Nat.add_assoc]

def codecArrayEquiv {α : Type*} (count width : ℕ)
    (encoding : (Fin width → Fin 256) ≃ α) :
    (Fin (count * width) → Fin 256) ≃ (Fin count → α) where
  toFun bytes i := encoding (fun j => bytes (finProdFinEquiv (i, j)))
  invFun values k := encoding.symm (values (finProdFinEquiv.symm k).1)
    (finProdFinEquiv.symm k).2
  left_inv bytes := by
    funext k
    simp only [Equiv.symm_apply_apply]
    exact congrArg bytes (finProdFinEquiv.apply_symm_apply k)
  right_inv values := by
    funext i
    simp only [Equiv.symm_apply_apply, Equiv.apply_symm_apply]

theorem codec_array_bytes {α : Type*} (count width : ℕ)
    (encoding : (Fin width → Fin 256) ≃ α) (values : Fin count → α) :
    codecBytes (count * width) (codecArrayEquiv count width encoding) values =
      (List.ofFn (fun i => codecBytes width encoding (values i))).flatten := by
  unfold codecBytes
  rw [List.ofFn_mul]
  apply congrArg List.flatten
  apply congrArg List.ofFn
  funext i
  apply congrArg List.ofFn
  funext j
  have index : (⟨i.val * width + j.val, by
      calc
        i.val * width + j.val < i.val * width + width := Nat.add_lt_add_left j.isLt _
        _ = (i.val + 1) * width := by rw [Nat.add_mul, Nat.one_mul]
        _ ≤ count * width := Nat.mul_le_mul_right width i.isLt⟩ : Fin (count * width)) =
      finProdFinEquiv (i, j) := by
    apply Fin.ext
    simp only [finProdFinEquiv, Equiv.coe_fn_mk, Nat.mul_comm, Nat.add_comm]
  change encoding.symm (values (finProdFinEquiv.symm _).1)
      (finProdFinEquiv.symm _).2 = encoding.symm (values i) j
  rw [index, Equiv.symm_apply_apply]

theorem codec_array_read {α : Type*} (count width : ℕ)
    (encoding : (Fin width → Fin 256) ≃ α) (bytes : ByteKey) (offset : ℕ) :
    codecRead (count * width) (codecArrayEquiv count width encoding) bytes offset =
      fun i => codecRead width encoding bytes (offset + width * i.val) := by
  funext i
  unfold codecRead codecArrayEquiv
  apply congrArg encoding
  funext j
  simp only [finProdFinEquiv, Equiv.coe_fn_mk]
  congr 1
  omega

end
end C10Probability
