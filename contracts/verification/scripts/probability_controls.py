"""Typed semantic controls for the standalone PMF project.

The definition-only fixtures must compile. Each unchanged `checked` proposition
passes on the original definition and rejects a changed behavior. This is
sensitivity evidence; rejection alone is not a theorem that a mutant is false.
"""
from pathlib import Path
import re


def definitions(source: str) -> str:
    # These source modules use only this deliberately restricted layout.
    # The normal build, full-source pins and theorem census are separate gates.
    return re.sub(r"^theorem\b.*?(?=^(?:theorem|def|abbrev|end)\b)", "", source,
                  flags=re.M | re.S)


def theorem(source: str, name: str) -> str:
    match = re.search(r"^theorem " + re.escape(name) +
                      r"\b.*?(?=^(?:theorem|def|abbrev|end)\b)", source,
                      flags=re.M | re.S)
    if not match:
        raise ValueError(f"missing control theorem {name}")
    return match.group(0).split("\n/--", 1)[0].replace("theorem " + name, "theorem checked", 1)


def append_check(source: str, check: str) -> str:
    ending = "end\nend C10Probability\n"
    if not source.endswith(ending):
        raise ValueError("unexpected control module layout")
    return source[:-len(ending)] + check + "\n" + ending


def cases(project: Path) -> list[dict]:
    src = {p.stem: p.read_text() for p in (project / "C10Probability").glob("*.lean")}
    out = []

    def add(name, module, old, new, check, expected=False):
        base = definitions(src[module])
        if base.count(old) != 1:
            raise ValueError(f"{name}: expected one definition site, got {base.count(old)}")
        changed = base.replace(old, new, 1)
        # All fixtures import the distribution constructor explicitly.
        prefix = "import Mathlib.Probability.Distributions.Uniform\n"
        out.append({"name": name, "definition": prefix + changed,
                    "baseline": prefix + append_check(base, check),
                    "checked": prefix + append_check(changed, check),
                    "expected": expected})

    first = """theorem checked :
    grind (PMF.pure true) id 0 1 (some (0, true)) = 1 := by
  simp [grind]
"""
    second = """theorem checked :
    grind (PMF.uniformOfFintype Bool) id 0 2 (some (1, true)) =
      (2 : ℝ≥0∞)⁻¹ * (2 : ℝ≥0∞)⁻¹ := by
  norm_num [grind, PMF.bind_apply, PMF.pure_apply, tsum_fintype] <;> simp
"""
    add("zero-budget", "Grind", "| 0 => PMF.pure none",
        "| 0 => p.map (fun x => some (start, x))",
        """theorem checked : grind (PMF.pure true) id 0 0 none = 1 := by
  simp [grind]
""")
    add("acceptance-branch", "Grind", "if accept x then PMF.pure",
        "if !accept x then PMF.pure", first)
    add("first-counter", "Grind", "PMF.pure (some (start, x))",
        "PMF.pure (some (start + 1, x))", first)
    add("returned-value", "Grind", "PMF.pure (some (start, x))",
        "PMF.pure none", first)
    add("retry-counter", "Grind", "else grind p accept (start + 1) n",
        "else grind p accept start n", second)
    add("retry-budget", "Grind", "else grind p accept (start + 1) n",
        "else grind p accept (start + 1) 0", second)
    add("counter-preserving", "Grind", "else grind p accept (start + 1) n",
        "else grind p accept (1 + start) n", second, True)
    add("forgotten-value", "Grind", ".map (Option.map Prod.snd)",
        ".map (fun _ => none)", """theorem checked :
    samples (PMF.pure true) id 1 (some true) = 1 := by
  rw [samples, grind, PMF.pure_bind]
  simp only [id_eq, Bool.true_eq, ↓reduceIte]
  rw [PMF.pure_map]
  simp
""")
    add("returned-event", "Returned", "result.any event", "result.any (fun _ => true)",
        """theorem checked :
    returnedMass (PMF.pure true) id (fun _ => false) 1 = 0 := by
  simp [returnedMass, acceptMass, samples, grind, PMF.map, PMF.pure_apply]
""")
    add("wots-target", "Projections", "= 205)", "= 204)",
        theorem(src["Projections"], "wots_acceptance_nonvacuous"))
    add("wots-length", "Projections", "Fin 43 → Fin 8", "Fin 42 → Fin 8",
        theorem(src["Projections"], "wots_atom_real"))
    add("wots-radix", "Projections", "Fin 43 → Fin 8", "Fin 43 → Fin 16",
        theorem(src["Projections"], "wots_atom_real"))
    add("fors-width", "Projections", "abbrev ForsField := Fin 2048",
        "abbrev ForsField := Fin 1024", theorem(src["Projections"], "fors_mass_exact"))
    add("fors-zero-test", "Projections", "decide (field = 0)", "decide (field = 1)",
        theorem(src["Projections"], "fors_acceptance_nonvacuous"))
    add("fors-preserving", "Projections", "decide (field = 0)", "decide (0 = field)",
        theorem(src["Projections"], "fors_mass_exact"), True)
    add("extended-cap", "Projections", "def signingBudget : ℕ := 10000000",
        "def signingBudget : ℕ := 10000001", """theorem checked (p : PMF Bool) :
    grind p id 0 signingBudget (some (10000000, true)) = 0 := by
  rw [grind_some]
  norm_num [signingBudget]
""")
    add("shortened-cap", "Projections", "def signingBudget : ℕ := 10000000",
        "def signingBudget : ℕ := 9999999", """theorem checked (p : PMF Bool) :
    grind p id 0 signingBudget (some (9999999, true)) =
      rejectMass p id ^ 9999999 * p true := by
  rw [grind_some]
  norm_num [signingBudget]
""")
    add("cached-resampling", "Boundaries", "grind (PMF.pure x) accept 0 n",
        "grind p accept 0 n", """theorem checked :
    cached (PMF.uniformOfFintype Bool) id 2 none = (2 : ℝ≥0∞)⁻¹ := by
  norm_num [cached, grind, PMF.bind_apply, PMF.pure_apply, tsum_fintype] <;> simp
""")
    add("digest-byte-order", "Digest",
        "toFun b i := b i.rev\n  invFun b i := b i.rev",
        "toFun b i := b i\n  invFun b i := b i",
        theorem(src["Digest"], "last_byte_is_low"))
    add("wots-digest-shift", "Digest", "radixField (2 ^ 127) (8 ^ 43) 1",
        "radixField (2 ^ 126) (8 ^ 43) 2",
        theorem(src["Digest"], "wots_129th_bit"))
    add("wots-128-bit-truncation", "Digest",
        "finFunctionFinEquiv.symm (wotsBlock d)",
        "finFunctionFinEquiv.symm ⟨(wotsBlock d).val % 2 ^ 128, "
        "Nat.lt_of_le_of_lt (Nat.mod_le _ _) (wotsBlock d).isLt⟩",
        theorem(src["Digest"], "wots_129th_bit"))
    add("wots-digit-order", "Digest",
        "finFunctionFinEquiv.symm (wotsBlock d)",
        "fun i => finFunctionFinEquiv.symm (wotsBlock d) i.rev",
        theorem(src["Digest"], "wots_129th_bit"))
    add("fors-digest-offset", "Digest", "radixField (2 ^ 113) 2048 (2 ^ 132)",
        "radixField (2 ^ 114) 2048 (2 ^ 131)",
        theorem(src["Digest"], "fors_first_bit"))
    add("fors-digest-width", "Digest",
        "radixField (2 ^ 113) 2048 (2 ^ 132) ((finCongr (by norm_num)) d)",
        "⟨d.val / 2 ^ 132 % 1024, Nat.lt_of_lt_of_le "
        "(Nat.mod_lt _ (by decide)) (by decide)⟩",
        theorem(src["Digest"], "fors_last_bit"))
    add("project-counter", "DigestGrind", "Prod.map id f", "Prod.map Nat.succ f",
        theorem(src["DigestGrind"], "project_some"))
    add("project-value-drop", "DigestGrind", "Option.map (Prod.map id f)",
        "fun _ => none", theorem(src["DigestGrind"], "project_some"))
    add("radix-field-reversal", "Uniform", ").symm x).1).2", ").symm x).1).2.rev",
        theorem(src["Uniform"], "radixField_value"))
    add("project-preserving", "DigestGrind", "Prod.map id f",
        "Prod.map (fun i => 0 + i) f", """theorem checked (f : α → β) (i : ℕ) (x : α) :
    projectResult f (some (i, x)) = some (i, f x) := by
  simp [projectResult]
""", True)
    add("digest-draw-preserving", "Digest", "PMF.uniformOfFintype Digest",
        "(PMF.uniformOfFintype Digest).map id", """theorem checked (d : Digest) :
    (digestDraw d).toReal = ((2 : ℝ) ^ 256)⁻¹ := by
  simp only [digestDraw, PMF.map_id, PMF.uniformOfFintype_apply, Digest,
    Fintype.card_fin, Nat.cast_pow, Nat.cast_ofNat, ENNReal.toReal_inv,
    ENNReal.toReal_pow, ENNReal.toReal_ofNat]
""", True)
    add("memo-cached-resample", "Memo", "| some x => PMF.pure (x, table)",
        "| some _ => p.map (fun x => (x, table))", """theorem checked :
    (memoQuery (PMF.pure true) (fun _ : Bool => some false) true).map Prod.fst =
      PMF.pure false := by
  simp [memoQuery, PMF.pure_map]
""")
    add("memo-cached-history", "Memo", "| some x => PMF.pure (x, table)",
        "| some x => PMF.pure (x, fun _ => none)",
        theorem(src["Memo"], "memoQuery_cached"))
    add("memo-store", "Memo", "(x, Function.update table key (some x))", "(x, table)",
        """theorem checked :
    (memoQuery (PMF.pure true) (fun _ : Bool => none) true).map
      (fun out => out.2 true) = PMF.pure (some true) := by
  simp [memoQuery, PMF.pure_map]
""")
    add("memo-other-key", "Memo", "Function.update table key (some x)",
        "fun _ => some x", """theorem checked :
    (memoQuery (PMF.pure true) (fun k : Bool => if k then none else some false) true).map
      (fun out => out.2 false) = PMF.pure (some false) := by
  simp [memoQuery, PMF.pure_map]
""")
    add("memo-search-counter", "Memo", "some (start, out.1)", "some (start + 1, out.1)",
        """theorem checked :
    (memoGrind (PMF.pure true) id (fun _ : Bool => none) 4 [true]).map Prod.fst =
      PMF.pure (some (4, true)) := by
  simp [memoGrind, memoQuery, PMF.bind_map, Function.comp_def,
    PMF.pure_bind, PMF.pure_map]
""")
    add("memo-search-acceptance", "Memo", "if accept out.1 then", "if !accept out.1 then",
        """theorem checked :
    (memoGrind (PMF.pure false) id (fun _ : Bool => none) 0 [true]).map Prod.fst =
      PMF.pure none := by
  simp [memoGrind, memoQuery, PMF.bind_map, Function.comp_def,
    PMF.pure_bind, PMF.pure_map]
""")
    add("counter-byte-order", "Counter", "bytesDigestEquiv.symm (counterDigest c)",
        "fun i => bytesDigestEquiv.symm (counterDigest c) i.rev", """theorem checked :
    (counterBytes 1 31).val = 1 := by decide
""")
    add("counter-block-width", "Counter", "List.ofFn (counterBytes c)",
        "(List.ofFn (counterBytes c)).take 4", theorem(src["Counter"], "counter_key_length"))
    add("counter-schedule-repeat", "Counter", "⟨start + i.val, by omega⟩",
        "⟨start, by have hi := i.isLt; omega⟩", """theorem checked :
    (counterSchedule [] 0 2 (by decide)).Nodup := by decide
""")
    add("collision-forgot-history", "KeyCollision", "trials * history + trials.choose 2",
        "trials.choose 2", """theorem checked : collisionPairs 1 1 = 1 := by decide
""")
    add("collision-forgot-pairs", "KeyCollision", "trials * history + trials.choose 2",
        "trials * history", """theorem checked : collisionPairs 0 2 = 1 := by decide
""")
    add("collision-forgot-insert", "KeyCollision", "keyCollision (insert key seen) n",
        "keyCollision seen n", theorem(src["KeyCollision"], "key_collision_bool_two"))
    add("memo-preserving", "Memo", "| some x => PMF.pure (x, table)",
        "| some x => PMF.pure (id x, table)",
        theorem(src["Memo"], "memoQuery_cached"), True)
    add("collision-charge-preserving", "KeyCollision", "trials * history + trials.choose 2",
        "history * trials + trials.choose 2", """theorem checked (h n : ℕ) :
    collisionPairs h n = n * h + n.choose 2 := by simp [collisionPairs, Nat.mul_comm]
""", True)
    add("schedule-length", "Schedules", "(drawList q n).map (List.cons key)",
        "drawList q n", """theorem checked :
    drawList (PMF.pure true) 2 = PMF.pure [true, true] := by
  simp [drawList, PMF.pure_bind, PMF.pure_map]
""")
    add("schedule-independent", "Schedules", "(drawList q n).map (List.cons key)",
        "(drawList q n).map (fun _ => List.replicate (n + 1) key)", """theorem checked :
    drawList (PMF.uniformOfFintype Bool) 2 [false, true] =
      (2 : ℝ≥0∞)⁻¹ * (2 : ℝ≥0∞)⁻¹ := by
  simp only [drawList, PMF.pure_map, PMF.map_bind, PMF.map_comp, Function.comp_def]
  norm_num [PMF.bind_apply, PMF.pure_apply, tsum_fintype]
""")
    add("scan-forgot-hit", "Schedules", "if key ∈ seen then true",
        "if key ∈ seen then false", theorem(src["Schedules"], "collisionScan_history"))
    add("scan-forgot-insert", "Schedules", "collisionScan (insert key seen) keys",
        "collisionScan seen keys", theorem(src["Schedules"], "collisionScan_repeat"))
    online_first = """theorem checked :
    (randomMemoGrind (PMF.pure true) (PMF.pure true) id (fun _ => none) 4 1).map
      Prod.fst = PMF.pure (some (4, true)) := by
  simp [randomMemoGrind, memoQuery, PMF.pure_bind, PMF.pure_map]
"""
    add("online-counter", "RandomGrind", "some (start, out.1)",
        "some (start + 1, out.1)", online_first)
    add("online-retry-table", "RandomGrind", "randomMemoGrind q p accept out.2",
        "randomMemoGrind q p accept table", """theorem checked :
    ((randomMemoGrind (PMF.pure true) fairReply id (fun _ => none) 0 2).map Prod.fst)
      none = (2 : ℝ≥0∞)⁻¹ := by
  simp only [randomMemoGrind, PMF.pure_bind, memoQuery, PMF.bind_map,
    Function.comp_def, Function.update_self, PMF.map_bind, PMF.pure_map]
  norm_num [fairReply, PMF.bind_apply, PMF.pure_apply, tsum_fintype]
  simp only [← ite_and]
  simp_rw [@and_comm (none = _) (_ = _)]
  simp [ite_and]
""")
    add("online-cache-start", "RandomGrind", "memoQuery p table key",
        "memoQuery p (fun _ => none) key", """theorem checked :
    (randomMemoGrind (PMF.pure true) (PMF.pure true) id (fun _ => some false) 0 1).map
      Prod.fst = PMF.pure none := by
  simp [randomMemoGrind, memoQuery, PMF.pure_bind, PMF.pure_map]
""")
    add("embedded-history-drop", "Transfer", "(table (embed key)).isSome",
        "false", theorem(src["Transfer"], "embeddedHistory_covers"))
    add("randomizer-half", "Randomizer", "(digestHalves d).1", "(digestHalves d).2",
        theorem(src["Randomizer"], "randomizer_first_retained_bit"))
    add("randomizer-byte-order", "Randomizer",
        "toFun bytes i := bytes i.rev\n  invFun bytes i := bytes i.rev",
        "toFun bytes i := bytes i\n  invFun bytes i := bytes i",
        theorem(src["Randomizer"], "randomizer_last_byte"))
    add("randomizer-truncate", "Randomizer", "(digestHalves d).1",
        "⟨(digestHalves d).1.val % 2 ^ 127, Nat.lt_of_lt_of_le "
        "(Nat.mod_lt _ (by decide)) (by norm_num)⟩",
        """theorem checked :
    (randomizerOfDigest ⟨2 ^ 255, by decide⟩).val = 2 ^ 127 := by decide
""")
    add("hmsg-pad-width", "Randomizer", "List.replicate 16 0", "List.replicate 15 0",
        theorem(src["Randomizer"], "hmsg_randomizer_length"))
    add("hmsg-pad-value", "Randomizer", "List.replicate 16 0", "List.replicate 16 1",
        theorem(src["Randomizer"], "hmsg_randomizer_zero_layout"))
    add("hmsg-domain-tag", "Randomizer", "List.replicate 32 255", "List.replicate 32 254",
        theorem(src["Randomizer"], "hmsg_randomizer_zero_layout"))
    add("hmsg-key-drop", "Randomizer", "List.ofFn (randomizerBytesEquiv.symm r)",
        "List.replicate 16 0", """theorem checked :
    hmsgRandomizerInput [] [] [] 0 ≠ hmsgRandomizerInput [] [] [] 1 := by decide
""")
    add("history-preserving", "Transfer", "(table (embed key)).isSome",
        "!(table (embed key)).isNone", """theorem checked [Fintype K]
    (table : Memo L α) (embed : K → L) (key : K) :
    key ∈ embeddedHistory table embed ↔ (table (embed key)).isSome := by
  cases ht : table (embed key) <;> simp [embeddedHistory, ht]
""", True)
    add("online-counter-preserving", "RandomGrind", "some (start, out.1)",
        "some (0 + start, out.1)", online_first, True)
    add("erase-hidden-inverted", "MemoView", "if hidden key then none else table key",
        "if !hidden key then none else table key", theorem(src["MemoView"], "eraseMemo_hidden"))
    memo_success = "PMF.pure (some (start, out.1), out.2)"
    add("memo-success-store", "Memo", memo_success, "PMF.pure (some (start, out.1), table)",
        theorem(src["Memo"], "memoGrind_immediate_state"))
    add("memo-success-continues", "Memo", memo_success,
        "(memoGrind p accept out.2 (start + 1) keys).map "
        "(fun rest => (some (start, out.1), rest.2))",
        theorem(src["Memo"], "memoGrind_immediate_state"))
    add("online-success-store", "RandomGrind", memo_success,
        "PMF.pure (some (start, out.1), table)",
        theorem(src["RandomGrind"], "randomMemoGrind_immediate_state"))
    add("online-success-continues", "RandomGrind", memo_success,
        "(randomMemoGrind q p accept out.2 (start + 1) n).map "
        "(fun rest => (some (start, out.1), rest.2))",
        theorem(src["RandomGrind"], "randomMemoGrind_immediate_state"))
    labelled_first = """theorem checked :
    (labelledMemoGrind (PMF.pure true) (PMF.pure false) id (fun _ => true)
      (fun _ : Bool => none) 4 1).map Prod.fst = PMF.pure (some (4, true, false)) := by
  simp [labelledMemoGrind, memoQuery, PMF.pure_map, PMF.pure_bind]
"""
    add("labelled-counter", "LabelledGrind", "some (start, label, out.1)",
        "some (start + 1, label, out.1)", labelled_first)
    add("labelled-result-drop", "LabelledGrind", "some (start, label, out.1)",
        "none", labelled_first)
    prefilled = theorem(src["DerivedGrind"], "derived_prefilled_label")
    immediate = theorem(src["DerivedGrind"], "derived_immediate_state")
    cached_hmsg = theorem(src["DerivedGrind"], "derived_cached_hmsg_failure")
    add("derived-r-cache-reset", "DerivedGrind", "memoQuery p table key",
        "memoQuery p (fun _ => none) key", prefilled)
    add("derived-hmsg-cache-reset", "DerivedGrind", "memoQuery p first.2",
        "memoQuery p (fun _ => none)", cached_hmsg)
    add("derived-r-store-drop", "DerivedGrind", "memoQuery p first.2",
        "memoQuery p table", immediate)
    derived_success = "PMF.pure (some (start, derive first.1, second.1), second.2)"
    add("derived-success-store", "DerivedGrind", derived_success,
        "PMF.pure (some (start, derive first.1, second.1), first.2)", immediate)
    add("derived-success-continues", "DerivedGrind", derived_success,
        "(derivedMemoGrind p derive encode accept second.2 (start + 1) keys).map "
        "(fun rest => (some (start, derive first.1, second.1), rest.2))", immediate)
    add("derived-returned-label", "DerivedGrind", "some (start, derive first.1, second.1)",
        "some (start, derive second.1, second.1)", prefilled)
    add("derived-returned-reply", "DerivedGrind", "some (start, derive first.1, second.1)",
        "some (start, derive first.1, first.1)", prefilled)
    add("derived-counter", "DerivedGrind", "some (start, derive first.1, second.1)",
        "some (start + 1, derive first.1, second.1)", prefilled)
    add("derived-acceptance", "DerivedGrind", "if accept second.1 then",
        "if !accept second.1 then", cached_hmsg)
    add("derived-retry-table", "DerivedGrind",
        "else derivedMemoGrind p derive encode accept second.2",
        "else derivedMemoGrind p derive encode accept first.2", """theorem checked :
    ((derivedMemoGrind fairReply (fun _ => true) (fun _ => (2 : ℕ)) id
      (fun _ => none) 0 [0, 1]).map Prod.fst) none = (2 : ENNReal)⁻¹ := by
  classical
  letI : DecidableEq (Option (ℕ × Bool × Bool) × Memo ℕ Bool) := Classical.decEq _
  have split_sum (c : Prop) [Decidable c] (a b : ENNReal) :
      (if c then a + b else 0) = (if c then a else 0) + (if c then b else 0) := by
    split_ifs <;> simp
  have atom_sum (z : Option (ℕ × Bool × Bool) × Memo ℕ Bool) (v : ENNReal) :
      (∑' a : Option (ℕ × Bool × Bool) × Memo ℕ Bool,
        if none = a.1 then (if a = z then v else 0) else 0) =
          if none = z.1 then v else 0 := by
    rw [tsum_eq_single z (by intro a ha; simp [ha])]
    simp
  simp only [derivedMemoGrind, memoQuery, PMF.bind_map, Function.comp_def, PMF.map_bind]
  norm_num [fairReply, PMF.bind_apply, PMF.pure_apply, tsum_fintype]
  simp only [split_sum, ENNReal.tsum_add, atom_sum]
  simp [ENNReal.inv_two_add_inv_two]
  rw [← mul_add, ENNReal.inv_two_add_inv_two, mul_one]
""")
    add("r-input-tag", "SharedRandomizer", "[82, 95, 103, 114, 105, 110, 100]",
        "[83, 95, 103, 114, 105, 110, 100]",
        theorem(src["SharedRandomizer"], "r_deterministic_layout"))
    add("r-input-random-drop", "SharedRandomizer", "secret ++ rGrindTag ++ random ++ message",
        "secret ++ rGrindTag ++ message", theorem(src["SharedRandomizer"], "r_hedged_layout"))
    add("r-input-nonce-order", "SharedRandomizer",
        "counterKey (rInputStem secret random message) nonce",
        "counterKey (rInputStem secret random []) nonce ++ message",
        theorem(src["SharedRandomizer"], "r_deterministic_layout"))
    add("r-domain-hedged", "SharedRandomizer", "key.length = 119", "key.length = 120",
        """theorem checked :
    rInputDomain (rDerivationInput (List.replicate 32 1) (List.replicate 16 2)
      (List.replicate 32 3) 4) = true := by decide
""")
    add("r-domain-hmsg", "SharedRandomizer", "key.length = 119", "key.length = 160",
        theorem(src["SharedRandomizer"], "hmsg_input_visible"))
    marked = theorem(src["SharedRandomizer"], "hmsg_marked_layout")
    add("hmsg-seed-root-order", "Randomizer", "(seed ++ root)", "(root ++ seed)", marked)
    add("hmsg-r-padding-order", "Randomizer",
        "List.ofFn (randomizerBytesEquiv.symm r) ++ List.replicate 16 0",
        "List.replicate 16 0 ++ List.ofFn (randomizerBytesEquiv.symm r)", marked)
    add("hmsg-message-suffix-order", "Randomizer", "(message ++ List.replicate 32 255)",
        "(List.replicate 32 255 ++ message)", marked)
    add("erase-hidden-preserving", "MemoView", "if hidden key then none else table key",
        "if hidden key = true then none else table key",
        theorem(src["MemoView"], "eraseMemo_hidden"), True)
    add("derived-counter-preserving", "DerivedGrind", "some (start, derive first.1, second.1)",
        "some (0 + start, derive first.1, second.1)", prefilled, True)

    # Bounded adaptive clients and observational collision instrumentation.
    add("randomized-cache-reset", "QueryProgram", "evalProgram p program table",
        "evalProgram p program (fun _ => none)",
        theorem(src["QueryProgram"], "randomizedProgram_pure"))
    add("adaptive-return-table", "QueryProgram", "PMF.pure (value, table)",
        "PMF.pure (value, fun _ => none)", theorem(src["QueryProgram"], "evalProgram_done"))
    query_step = "evalProgram p (next out.1) out.2"
    query_one = theorem(src["QueryProgram"], "evalProgram_one")
    add("adaptive-query-store", "QueryProgram", query_step,
        "evalProgram p (next out.1) table", query_one)
    add("adaptive-cache-reset", "QueryProgram", "memoQuery p table key",
        "memoQuery p (fun _ => none) key", """theorem checked :
    evalProgram (PMF.pure true) (.query false (fun reply => .done (n := 0) reply))
      (fun _ : Bool => some false) = PMF.pure (false, fun _ => some false) := by
  simp [evalProgram, memoQuery, PMF.pure_map]
""")
    add("adaptive-reply-resample", "QueryProgram", query_step,
        "p.bind (fun value => evalProgram p (next value) out.2)", query_one)
    add("adaptive-key-fixed", "QueryProgram",
        ".query first (fun second => .done (first, second))",
        ".query true (fun second => .done (first, second))",
        theorem(src["QueryProgram"], "adaptiveBool_cached_branch"))
    add("observer-cache-store", "CollisionObserver",
        "Function.update state.cache key (some value)", "state.cache",
        theorem(src["CollisionObserver"], "observedQuery_erases"))
    seen_check = """theorem checked [DecidableEq K] [DecidableEq V]
    (project : α → V) (state : CollisionView K α V) (key : K) (value : α) :
    (recordReply project state key value).seen = insert (project value) state.seen := by
  simp [recordReply]
"""
    add("observer-seen-insert", "CollisionObserver", "insert (project value) state.seen",
        "state.seen", seen_check)
    add("observer-prior-flag", "CollisionObserver",
        "state.bad || decide (project value ∈ state.seen)",
        "decide (project value ∈ state.seen)",
        theorem(src["AdaptiveExamples"], "observer_retains_prior_flag"))
    add("observer-collision-drop", "CollisionObserver", "decide (project value ∈ state.seen)",
        "false", """theorem checked :
    (recordReply id
      (⟨fun key : Bool => if key then none else some true, {true}, false⟩ :
        CollisionView Bool Bool Bool) true true).bad = true := by decide
""")
    add("observer-collision-invert", "CollisionObserver", "decide (project value ∈ state.seen)",
        "decide (project value ∉ state.seen)", """theorem checked :
    (recordReply id (emptyView : CollisionView Bool Bool Bool) false true).bad = false := by
  simp [recordReply, emptyView]
""")
    add("observer-cached-resample", "CollisionObserver", "| some value => PMF.pure (value, state)",
        "| some value => p.map (fun reply => (reply, recordReply project state key reply))",
        theorem(src["CollisionObserver"], "observedQuery_cached"))
    add("observer-query-state", "CollisionObserver",
        "observeProgram p project (next out.1) out.2",
        "observeProgram p project (next out.1) state", """theorem checked :
    observeProgram (PMF.pure true) id
      (.query false (fun reply => .done (n := 0) reply)) emptyView =
        PMF.pure (true, (⟨Function.update (fun _ : Bool => none) false (some true),
          {true}, false⟩ : CollisionView Bool Bool Bool)) := by
  simp [observeProgram, observedQuery, recordReply, emptyView, PMF.pure_map]
""")
    observer_return = """theorem checked (state : CollisionView Bool Bool Bool) :
    observeProgram fairReply id (.done (n := 0) true) state = PMF.pure (true, state) := by rfl
"""
    add("observer-return-history", "CollisionObserver",
        "| _, .done value, state => PMF.pure (value, state)",
        "| _, .done value, state => PMF.pure (value, ⟨state.cache, ∅, state.bad⟩)",
        observer_return)
    add("observer-return-flag", "CollisionObserver",
        "| _, .done value, state => PMF.pure (value, state)",
        "| _, .done value, state => PMF.pure (value, ⟨state.cache, state.seen, false⟩)",
        observer_return)
    add("collision-input-identity", "CollisionObserver",
        "project value = project reply → key = other",
        "project value = project reply → value = reply",
        theorem(src["AdaptiveExamples"], "two_entries_collision"))
    add("collision-projection", "CollisionObserver",
        "project value = project reply → key = other",
        "value = reply → key = other", """theorem checked :
    ¬ CollisionFree (fun _ : Bool => false) (fun key : Bool => some key) := by
  unfold CollisionFree
  decide
""")
    add("observer-history-coverage", "CollisionObserver",
        "cache key = some value → project value ∈ seen",
        "cache key = some value → project value ∉ seen", """theorem checked :
    SeenCovers id (fun _ : Bool => some true) {true} := by
  unfold SeenCovers
  decide
""")
    add("observer-validity-guard", "CollisionObserver",
        "state.bad = false → CollisionFree project state.cache",
        "state.bad = true → CollisionFree project state.cache", """theorem checked :
    ¬ ViewValid id (⟨fun _ : Bool => some false, {false}, false⟩ :
      CollisionView Bool Bool Bool) := by
  unfold ViewValid SeenCovers CollisionFree
  decide
""")
    add("observer-initial-flag", "CollisionObserver",
        "⟨fun _ => none, ∅, false⟩", "⟨fun _ => none, ∅, true⟩", """theorem checked :
    (emptyView : CollisionView Bool Bool Bool).bad = false := by rfl
""")
    add("adaptive-budget-preserving", "QueryProgram", "QueryProgram K α R (n + 1)",
        "QueryProgram K α R (Nat.succ n)", query_one, True)
    add("observer-flag-preserving", "CollisionObserver",
        "state.bad || decide (project value ∈ state.seen)",
        "decide (project value ∈ state.seen) || state.bad",
        theorem(src["AdaptiveExamples"], "observer_retains_prior_flag"), True)
    add("observer-seen-preserving", "CollisionObserver", "insert (project value) state.seen",
        "{project value} ∪ state.seen", seen_check, True)
    # Public-query traces, independent-secret prefixes and first-call transfer.
    trace_erases = theorem(src["QueryTrace"], "traceProgram_erases")
    add("trace-return-cache", "QueryTrace", "PMF.pure ⟨value, table, []⟩",
        "PMF.pure ⟨value, (fun _ => none), []⟩",
        theorem(src["QueryTrace"], "traceProgram_done"))
    trace_step = "traceProgram p (next out.1) out.2"
    add("trace-query-cache", "QueryTrace", trace_step,
        "traceProgram p (next out.1) table", trace_erases)
    add("trace-reply-resample", "QueryTrace", "(traceProgram p (next out.1) out.2).map",
        "(p.bind (fun value => traceProgram p (next value) out.2)).map", trace_erases)
    add("trace-cached-resample", "QueryTrace", "memoQuery p table key",
        "memoQuery p (fun _ => none) key", trace_erases)
    traced_repeats = """theorem checked :
    ((traceProgram (PMF.pure true)
      (.query false (fun _ => .query false (fun reply => .done (n := 0) reply)))
      (fun _ => some false)).map (fun out => out.queries)) = PMF.pure [false, false] := by
  simp [traceProgram, memoQuery, PMF.pure_map]
"""
    add("trace-omit-query", "QueryTrace", "key :: rest.queries", "rest.queries", traced_repeats)
    add("trace-omit-tail", "QueryTrace", "key :: rest.queries", "[key]", traced_repeats)
    traced_order = """theorem checked :
    ((traceProgram (PMF.pure true)
      (.query false (fun _ => .query true (fun reply => .done (n := 0) reply)))
      (fun _ => none)).map (fun out => out.queries)) = PMF.pure [false, true] := by
  simp [traceProgram, memoQuery, PMF.pure_map]
"""
    add("trace-query-order", "QueryTrace", "key :: rest.queries",
        "rest.queries ++ [key]", traced_order)
    add("randomized-trace-reset", "QueryTrace", "traceProgram p program table",
        "traceProgram p program (fun _ => none)", """theorem checked :
    randomizedTrace fairReply (PMF.pure (.done (n := 0) true)) (fun _ : Bool => some false) =
      PMF.pure (⟨true, fun _ => some false, []⟩ : TraceOutput Bool Bool Bool) := by
  simp [randomizedTrace, traceProgram]
""")
    candidates = """theorem checked :
    prefixCandidates (some : Bool → Option Bool) [false, true] = {false, true} := by
  ext value
  cases value <;> simp [prefixCandidates]
"""
    add("prefix-candidates-drop", "PrefixGuess", "(queries.filterMap decode).toFinset",
        "∅", candidates)
    add("prefix-candidates-tail", "PrefixGuess", "queries.filterMap decode",
        "(queries.take 1).filterMap decode", candidates)
    add("prefix-hit-invert", "PrefixGuess", "out.1 ∈ prefixCandidates decode out.2.queries",
        "out.1 ∉ prefixCandidates decode out.2.queries", """theorem checked :
    prefixHit (some : Bool → Option Bool)
      (false, (⟨true, fun _ => none, []⟩ : TraceOutput Bool Bool Bool)) = false := by
  simp [prefixHit, prefixCandidates]
""")
    public_prelude = theorem(src["PrefixGuess"], "secretPrelude_public")
    add("secret-prelude-reset", "PrefixGuess", "randomizedTrace p client table",
        "randomizedTrace p client (fun _ => none)", public_prelude)
    add("secret-prelude-cache-drop", "PrefixGuess", "(secret, out)",
        "(secret, {out with cache := fun _ => none})", public_prelude)
    add("prefix-short-padding", "SecretPrefix", "else none", "else some 0",
        theorem(src["SecretPrefix"], "decodeSecretPrefix_short"))
    prefix_byte = "key[i.val]'(lt_of_lt_of_le i.isLt h)"
    add("prefix-byte-order", "SecretPrefix", prefix_byte,
        "key[31 - i.val]'(by omega)", theorem(src["SecretPrefix"], "secret_prefix_first_byte"))
    add("prefix-value-change", "SecretPrefix",
        "some (bytesDigestEquiv fun i => " + prefix_byte + ")",
        "some ((bytesDigestEquiv fun i => " + prefix_byte + ") + 1)",
        theorem(src["SecretPrefix"], "secret_prefix_last_byte"))
    add("secret-bytes-reverse", "SecretPrefix", "List.ofFn (bytesDigestEquiv.symm secret)",
        "List.ofFn (fun i : Fin 32 => bytesDigestEquiv.symm secret i.rev)", """theorem checked :
    secretBytes 1 = List.replicate 31 0 ++ [1] := by decide
""")
    add("prefix-suffix-dependence", "SecretPrefix", prefix_byte,
        "key[key.length - 32 + i.val]'(by omega)", """theorem checked :
    decodeSecretPrefix (List.replicate 32 0 ++ [1]) = some 0 := by decide
""")
    valid_request = """theorem checked :
    RequestValid ⟨[], List.replicate 32 0, List.replicate 32 0, List.replicate 32 0⟩ := by
  unfold RequestValid
  decide
"""
    add("request-random-width", "PreludeTransfer", "request.random.length = 16",
        "request.random.length = 15", """theorem checked :
    ¬ RequestValid ⟨List.replicate 15 0, List.replicate 32 0,
      List.replicate 32 0, List.replicate 32 0⟩ := by
  unfold RequestValid
  decide
""")
    for field in ("message", "seed", "root"):
        add("request-" + field + "-width", "PreludeTransfer",
            "request." + field + ".length = 32", "request." + field + ".length = 31",
            valid_request)
    # The consuming quantitative theorem includes its own local proved bridge
    # helpers, so a changed executed program cannot hide behind an imported
    # original implementation. Every error must still be inside `checked`.
    transfer = theorem(src["PreludeTransfer"], "prelude_event_bounds")
    helpers = []
    for name in ("preludeIndependent_with_secret", "prelude_grind_good"):
        local = theorem(src["PreludeTransfer"], name).replace("theorem checked", "have " + name, 1)
        helpers.append("\n".join("  " + line for line in local.splitlines()))
    head, proof = transfer.split(":= by\n", 1)
    transfer = head + ":= by\n" + "\n".join(helpers) + "\n" + proof
    add("prelude-shared-cache-reset", "PreludeTransfer", "sharedRandomizerSearch prior.2.cache",
        "sharedRandomizerSearch (fun _ => none)", transfer)
    add("prelude-shared-result-drop", "PreludeTransfer", "forgetLabel out.1", "none", transfer)
    add("prelude-shared-counter-shift", "PreludeTransfer", "forgetLabel out.1",
        "(forgetLabel out.1).map (fun pair => (pair.1 + 1, pair.2))", transfer)
    add("prelude-shared-digest-drop", "PreludeTransfer", "forgetLabel out.1",
        "(forgetLabel out.1).map (fun pair => (pair.1, 0))", transfer)
    add("prelude-shared-budget-zero", "PreludeTransfer", ".root n hb).map",
        ".root 0 (by omega)).map", transfer)
    add("prelude-shared-message-swap", "PreludeTransfer", "(request prior.2.value).message",
        "(request prior.2.value).seed", transfer)
    independent = theorem(src["PreludeTransfer"], "preludeIndependent_with_secret")
    add("prelude-independent-cache-reset", "PreludeTransfer", "randomizerMemoSearch prior.cache",
        "randomizerMemoSearch (fun _ => none)", independent)
    add("prelude-independent-counter-shift", "PreludeTransfer", "(prior.value, out.1)",
        "(prior.value, out.1.map (fun pair => (pair.1 + 1, pair.2)))", independent)
    add("trace-cons-preserving", "QueryTrace", "key :: rest.queries",
        "[key] ++ rest.queries", traced_order, True)
    add("prefix-set-preserving", "PrefixGuess", "(queries.filterMap decode).toFinset",
        "((queries.filterMap decode).reverse).toFinset", candidates, True)
    add("prefix-guard-preserving", "SecretPrefix", "if h : 32 ≤ key.length then",
        "if h : key.length ≥ 32 then", theorem(src["SecretPrefix"], "secret_prefix_last_byte"), True)
    add("request-alternative-preserving", "PreludeTransfer",
        "request.random.length = 0 ∨ request.random.length = 16",
        "request.random.length = 16 ∨ request.random.length = 0", valid_request, True)

    # Interleaved public/private calls: mutation consumers must connect to the
    # executed definitions, including locally proved composition helpers.
    mapped = theorem(src["QueryMap"], "mapProgram_id")
    add("mapped-tail-key-constant", "QueryMap", "mapProgram encode (next reply)",
        "mapProgram (fun _ => encode key) (next reply)", mapped)
    add("mapped-reply-preserving", "QueryMap", "mapProgram encode (next reply)",
        "mapProgram encode (next (id reply))", mapped, True)
    public_length = theorem(src["QueryMap"], "traceProgram_public_length")
    add("public-budget-no-charge", "QueryMap", "PublicBudget (next reply) (q - 1)",
        "PublicBudget (next reply) q", public_length)
    add("public-budget-zero-allowed", "QueryMap", "0 < q ∧", "True ∧", public_length)
    add("private-budget-increases", "QueryMap", "| _, .query (.inr _) next, q => ∀ reply, PublicBudget (next reply) q",
        "| _, .query (.inr _) next, q => ∀ reply, PublicBudget (next reply) (q + 1)", public_length)
    add("public-query-omitted", "QueryMap", "| .inl key => some key", "| .inl key => none",
        """theorem checked :
    publicQueries ([.inl false, .inr (), .inl true] : List (Sum Bool Unit)) = [false, true] := by
  simp [publicQueries]
""")
    private_budget = """theorem checked :
    PublicBudget (.query (.inr ()) (fun _ : Bool => .query (.inl false)
      (fun _ => .done (n := 0) ()))) 1 := by
  simp [PublicBudget]
"""
    add("private-budget-charged", "QueryMap", "| _, .query (.inr _) next, q => ∀ reply, PublicBudget (next reply) q",
        "| _, .query (.inr _) next, q => ∀ reply, PublicBudget (next reply) (q - 1)", private_budget)
    add("public-budget-pred-preserving", "QueryMap", "PublicBudget (next reply) (q - 1)",
        "PublicBudget (next reply) q.pred", public_length, True)

    stopped = theorem(src["StoppedProgram"], "stoppedProgram_trace")
    add("stopped-return-absent", "StoppedProgram", "| _, .done value, _ => PMF.pure (some value)",
        "| _, .done value, _ => PMF.pure none", stopped)
    add("stopped-guard-inverted", "StoppedProgram", "if bad key then", "if !bad key then", stopped)
    add("stopped-guard-disabled", "StoppedProgram", "if bad key then", "if false then", stopped)
    add("stopped-cache-reset", "StoppedProgram", "memoQuery p table (encode key)",
        "memoQuery p (fun _ => none) (encode key)", stopped)
    add("stopped-cache-discarded", "StoppedProgram",
        "stoppedProgram p encode bad (next reply.1) reply.2",
        "stoppedProgram p encode bad (next reply.1) table", stopped)
    add("stopped-continuation-resampled", "StoppedProgram",
        "stoppedProgram p encode bad (next reply.1) reply.2",
        "p.bind fun fresh => stoppedProgram p encode bad (next fresh) reply.2", stopped)
    add("stopped-event-includes-abort", "StoppedProgram", "| none => False | some value => value ∈ event",
        "| none => True | some value => value ∈ event",
        theorem(src["StoppedProgram"], "stoppedProgram_retained_le"))
    add("stopped-trace-all-queries", "StoppedProgram", "out.queries.any bad", "out.queries.all bad", stopped)
    add("stopped-guard-preserving", "StoppedProgram", "if bad key then", "if true = bad key then", stopped, True)

    add("good-injectivity-reversed", "MemoRelabel",
        "encode first = encode second → first = second",
        "first = second → encode first = encode second",
        theorem(src["MemoRelabel"], "tablesRelate_update"))
    related = theorem(src["MemoRelabel"], "stoppedProgram_relabel")
    update = theorem(src["MemoRelabel"], "tablesRelate_update").replace("theorem checked", "have tablesRelate_update", 1)
    head, proof = related.split(":= by\n", 1)
    related = head + ":= by\n" + "\n".join("  " + line for line in update.splitlines()) + "\n" + proof
    add("cache-relation-erased", "MemoRelabel", "physical (encode key) = ideal key",
        "ideal key = ideal key", related)

    add("public-prefix-decoding-omitted", "PrivateQueries", "| .inl key => decode key",
        "| .inl key => none", theorem(src["PrivateQueries"], "publicCandidates_eq"))
    bad_trace = theorem(src["PrivateQueries"], "privateBad_trace")
    add("private-queries-count-as-prefix-hits", "PrivateQueries",
        "decide (publicDecode decode key = some secret)",
        "match key with | .inl key => decide (decode key = some secret) | .inr _ => true", bad_trace)
    add("private-prefix-hit-inverted", "PrivateQueries", "decide (publicDecode decode key = some secret)",
        "!decide (publicDecode decode key = some secret)", bad_trace)

    interleaved = theorem(src["PrivateTransfer"], "private_event_bounds")
    helpers = []
    for name in ("privateKey_good_injective", "private_program_bounds", "private_client_bounds", "private_mixture_bounds"):
        local = theorem(src["PrivateTransfer"], name).replace("theorem checked", "have " + name, 1)
        helpers.append("\n".join("  " + line for line in local.splitlines()))
    head, proof = interleaved.split(":= by\n", 1)
    interleaved = head + ":= by\n" + "\n".join(helpers) + "\n" + proof
    add("private-secret-fixed", "PrivateTransfer",
        "secretDraw.bind fun secret => privateSharedAt p encode secret client",
        "secretDraw.bind fun _ => privateSharedAt p encode (Classical.choose secretDraw.support_nonempty) client",
        interleaved)
    add("private-client-randomness-discarded", "PrivateTransfer", "client.bind fun program =>",
        "(PMF.pure (Classical.choose client.support_nonempty)).bind fun program =>", interleaved)
    add("independent-client-randomness-discarded", "PrivateTransfer",
        "randomizedProgram p client (fun _ => none)",
        "randomizedProgram p (PMF.pure (Classical.choose client.support_nonempty)) (fun _ => none)", interleaved)
    add("private-prefix-charge-suppressed", "PrivateTransfer",
        "fun out => prefixHit (publicDecode decode) (secret, out)", "fun out => false", interleaved)
    add("private-secret-preserving", "PrivateTransfer",
        "secretDraw.bind fun secret => privateSharedAt p encode secret client",
        "secretDraw.bind fun secret => privateSharedAt p encode (id secret) client", interleaved, True)

    concrete = theorem(src["PrivateSecret"], "prefixedPrivateInput_decodes")
    add("private-secret-prefix-order", "PrivateSecret", "secretBytes secret ++ tail", "tail ++ secretBytes secret", concrete)
    add("private-secret-prefix-value", "PrivateSecret", "secretBytes secret ++ tail", "secretBytes 0 ++ tail",
        """theorem checked (secret : Digest) (tail : ByteKey) :
    decodeSecretPrefix (prefixedPrivateInput secret tail) = some secret := by
  unfold prefixedPrivateInput
  rw [decodeSecretPrefix_secret]
""")
    add("private-tail-discarded", "PrivateSecret", "secretBytes secret ++ tail", "secretBytes secret",
        theorem(src["PrivateSecret"], "prefixedPrivateInput_injective"))
    add("private-tail-reversed", "PrivateSecret", "secretBytes secret ++ tail", "secretBytes secret ++ tail.reverse",
        theorem(src["PrivateSecret"], "prefixedPrivateInput_r"))
    add("private-prefix-preserving", "PrivateSecret", "secretBytes secret ++ tail", "secretBytes secret ++ id tail", concrete, True)

    # Concrete grinder compilation and persistent prelude/continuation state.
    # Keep the bridge proofs local to the consumer, including the actual
    # session definitions; no imported original bridge can mask a mutation.
    def local_consumer(module, name, helpers):
        check = theorem(src[module], name)
        head, proof = check.split(":= by\n", 1)
        local = []
        for helper in helpers:
            text = theorem(src[module], helper).replace("theorem checked", "have " + helper, 1)
            if module == "ProgramComposition":
                # The composed program returns T, while its first stage returns R.
                text = re.sub(r"\bR\b", "T", text)
            local.append("\n".join("  " + line for line in text.splitlines()))
        return head + ":= by\n" + "\n".join(local) + "\n" + proof

    add("reserve-later-keys-fixed", "ProgramComposition",
        "reserveProgram extra (next reply)",
        "mapProgram (fun _ => key) (reserveProgram extra (next reply))",
        theorem(src["ProgramComposition"], "evalProgram_reserve"))
    composed = local_consumer("ProgramComposition", "evalProgram_bind",
        ["evalProgram_cast", "evalProgram_reserve"])
    composed = composed.replace("evalProgram_reserve, evalProgram]",
        "evalProgram_reserve, evalProgram, mapProgram_id]")
    add("bound-continuation-keys-fixed", "ProgramComposition",
        "bindProgram (next reply) after",
        "bindProgram (next reply) (fun value => mapProgram (fun _ => key) (after value))", composed)
    add("bound-continuation-preserving", "ProgramComposition",
        "reserveProgram n (after value)", "reserveProgram n (mapProgram id (after value))", composed, True)

    compiled = theorem(src["GrindProgram"], "evalProgram_mapped_derived")
    add("compiled-first-input-repeated", "GrindProgram",
        "derivedProgram firstKey derive encode accept (start + 1) keys",
        "derivedProgram (fun _ => firstKey key) derive encode accept (start + 1) keys", compiled)
    add("compiled-second-input-reused", "GrindProgram", ".query (encode (derive first))",
        ".query (firstKey key)", compiled)
    add("compiled-accept-inverted", "GrindProgram", "if accept second then", "if !accept second then", compiled)
    add("compiled-first-counter", "GrindProgram", ".done (some (start, derive first, second))",
        ".done (some (start + 1, derive first, second))", compiled)
    add("compiled-selected-label", "GrindProgram", ".done (some (start, derive first, second))",
        ".done (some (start, derive second, second))", compiled)
    add("compiled-returned-digest", "GrindProgram", ".done (some (start, derive first, second))",
        ".done (some (start, derive first, first))", compiled)
    add("compiled-retry-counter", "GrindProgram",
        "derivedProgram firstKey derive encode accept (start + 1) keys",
        "derivedProgram firstKey derive encode accept start keys", compiled)
    add("compiled-continues-success", "GrindProgram", ".done (some (start, derive first, second))",
        "derivedProgram firstKey derive encode accept (start + 1) keys", compiled)
    add("compiled-counter-preserving", "GrindProgram",
        "derivedProgram firstKey derive encode accept (start + 1) keys",
        "derivedProgram firstKey derive encode accept (1 + start) keys",
        compiled.replace("[ha, Bool.false_eq_true, ↓reduceIte]",
                         "[ha, Bool.false_eq_true, ↓reduceIte, Nat.add_comm]"), True)

    tail = theorem(src["GrindInterface"], "prefixed_tail_counter")
    add("private-tail-fields-reversed", "GrindInterface", "rGrindTag ++ random ++ message",
        "rGrindTag ++ message ++ random", tail)
    add("private-tail-tag-omitted", "GrindInterface", "rGrindTag ++ random ++ message",
        "random ++ message", tail)
    add("private-tail-association-preserving", "GrindInterface", "rGrindTag ++ random ++ message",
        "(rGrindTag ++ random) ++ message", tail, True)
    shared_compiler = local_consumer("GrindInterface", "privateRandomizerProgram_shared",
        ["prefixed_tail_counter", "prefixed_tail_schedule"])
    add("compiled-private-call-public", "GrindInterface", "derivedProgram Sum.inr randomizerOfDigest",
        "derivedProgram Sum.inl randomizerOfDigest", shared_compiler)
    add("compiled-randomizer-fixed", "GrindInterface", "derivedProgram Sum.inr randomizerOfDigest",
        "derivedProgram Sum.inr (fun _ : Digest => (0 : Randomizer))", shared_compiler)
    add("compiled-search-counter", "GrindInterface",
        "(forsAccept ∘ forsOfDigest) 0 (counterSchedule",
        "(forsAccept ∘ forsOfDigest) 1 (counterSchedule", shared_compiler)
    add("independent-private-cache-public", "GrindInterface",
        "((counterSchedule (rTailStem random message) 0 n hb).map Sum.inr)",
        "((counterSchedule (rTailStem random message) 0 n hb).map Sum.inl)",
        theorem(src["GrindInterface"], "privateRandomizerProgram_independent"))
    add("compiled-hmsg-seed-root", "GrindInterface",
        "derivedProgram Sum.inr randomizerOfDigest (Sum.inl ∘ hmsgRandomizerInput seed root message)",
        "derivedProgram Sum.inr randomizerOfDigest (Sum.inl ∘ hmsgRandomizerInput root seed message)", shared_compiler)

    session = local_consumer("GrindSession", "grindSession_event_bounds",
        ["grindSessionProgram_shared", "grindSessionProgram_independent", "grindSessionProgram_budget",
         "sharedGrindSession_client", "independentGrindSession_client", "grindSessionClient_budget"])
    session = session.replace("Function.comp_def,", "Function.comp_def, id_eq,")
    add("session-discards-grind-result", "GrindSession",
        "(request prior).seed (request prior).root n hb) (after prior)",
        "(request prior).seed (request prior).root n hb) (fun _ => after prior none)", session)
    add("shared-session-secret-fixed", "GrindSession",
        "digestDraw.bind fun secret => client.bind fun before =>",
        "digestDraw.bind fun _ => let secret : Digest := 0; client.bind fun before =>", session)
    add("shared-session-grind-cache-reset", "GrindSession", "sharedRandomizerSearch prior.2",
        "sharedRandomizerSearch (fun _ => none)", session)
    add("shared-session-after-cache-reset", "GrindSession",
        "(mapProgram (privateKey prefixedPrivateInput secret) (after prior.1 out.1)) out.2).map",
        "(mapProgram (privateKey prefixedPrivateInput secret) (after prior.1 out.1)) (fun _ => none)).map", session)
    add("shared-session-after-result-discard", "GrindSession",
        "(mapProgram (privateKey prefixedPrivateInput secret) (after prior.1 out.1)) out.2).map",
        "(mapProgram (privateKey prefixedPrivateInput secret) (after prior.1 none)) out.2).map", session)
    add("independent-session-grind-cache-reset", "GrindSession", "privateRandomizerSearch prior.2",
        "privateRandomizerSearch (fun _ => none)", session)
    add("independent-session-after-cache-reset", "GrindSession",
        "(evalProgram digestDraw (after prior.1 out.1) out.2).map",
        "(evalProgram digestDraw (after prior.1 out.1) (fun _ => none)).map", session)
    add("independent-session-after-result-discard", "GrindSession",
        "(evalProgram digestDraw (after prior.1 out.1) out.2).map",
        "(evalProgram digestDraw (after prior.1 none) out.2).map", session)
    add("shared-session-client-fixed", "GrindSession",
        "digestDraw.bind fun secret => client.bind fun before =>",
        "digestDraw.bind fun secret => (PMF.pure (Classical.choose client.support_nonempty)).bind fun before =>", session)
    add("session-secret-preserving", "GrindSession", "sharedRandomizerSearch prior.2 (secretBytes secret)",
        "sharedRandomizerSearch prior.2 (secretBytes (id secret))", session, True)
    add("session-after-table-preserving", "GrindSession",
        "(evalProgram digestDraw (after prior.1 out.1) out.2).map",
        "(evalProgram digestDraw (after prior.1 out.1) (id out.2)).map", session, True)

    # Accepted collisions: preserve actual cache execution, filter only the
    # observer, and derive the acceptance-weighted charge. Helpers that mention
    # a mutated definition are reproved locally inside the consumer.
    accepted_query = theorem(src["AcceptedObserver"], "acceptedQuery_erases")
    accepted_program = local_consumer("AcceptedObserver", "observeAcceptedProgram_erases",
        ["acceptedQuery_erases"])
    accepted_valid = theorem(src["AcceptedObserver"], "recordAcceptedReply_valid")
    accepted_flag = local_consumer("AcceptedObserver", "observeAcceptedProgram_collision_flag",
        ["recordAcceptedReply_valid", "acceptedQuery_valid", "observeAcceptedProgram_valid"])
    add("accepted-cache-store-omitted", "AcceptedObserver",
        "Function.update state.cache key (some value)", "state.cache", accepted_query)
    add("accepted-rejected-cache-omitted", "AcceptedObserver",
        "Function.update state.cache key (some value)",
        "if accept (project value) then Function.update state.cache key (some value) else state.cache",
        accepted_query)
    add("accepted-cached-resampling", "AcceptedObserver", "| some value => PMF.pure (value, state)",
        "| some _ => p.map (fun value => (value, state))", accepted_query)
    add("accepted-cached-history-loss", "AcceptedObserver", "| some value => PMF.pure (value, state)",
        "| some value => PMF.pure (value, emptyView)", accepted_query)
    add("accepted-next-reply-fixed", "AcceptedObserver", "(next out.1) out.2",
        "(next (Classical.choose p.support_nonempty)) out.2", accepted_program)
    add("accepted-next-cache-reset", "AcceptedObserver", "(next out.1) out.2",
        "(next out.1) emptyView", accepted_program)
    add("accepted-seen-insertion-omitted", "AcceptedObserver",
        "if accept (project value) then insert (project value) state.seen else state.seen",
        "state.seen", accepted_valid)
    add("accepted-rejected-seen-growth", "AcceptedObserver",
        "if accept (project value) then insert (project value) state.seen else state.seen",
        "insert (project value) state.seen",
        theorem(src["AcceptedExamples"], "rejected_reply_stored_without_growth"))
    add("accepted-flag-collision-omitted", "AcceptedObserver",
        "state.bad || (accept (project value) && decide (project value ∈ state.seen))",
        "state.bad", accepted_valid)
    add("accepted-flag-history-forgotten", "AcceptedObserver",
        "state.bad || (accept (project value) && decide (project value ∈ state.seen))",
        "accept (project value) && decide (project value ∈ state.seen)",
        theorem(src["AcceptedObserver"], "acceptedQuery_bad_persists"))
    add("accepted-flag-rejection-ignored", "AcceptedObserver",
        "state.bad || (accept (project value) && decide (project value ∈ state.seen))",
        "state.bad || decide (project value ∈ state.seen)", """theorem checked :
    (recordAcceptedReply id id (⟨fun _ : Bool => none, {false}, false⟩ : CollisionView Bool Bool Bool)
      true false).bad = false := by decide
""")
    add("accepted-spec-rejection-ignored", "AcceptedObserver",
        "accept (project value) = true → project value = project reply → key = other",
        "project value = project reply → key = other",
        theorem(src["AcceptedExamples"], "rejected_duplicates_are_accepted_collision_free"))
    add("accepted-spec-key-identity-waived", "AcceptedObserver",
        "accept (project value) = true → project value = project reply → key = other",
        "accept (project value) = true → project value = project reply → True",
        theorem(src["AcceptedExamples"], "accepted_prior_collision"))
    add("accepted-spec-projection-ignored", "AcceptedObserver",
        "accept (project value) = true → project value = project reply → key = other",
        "accept (project value) = true → True → key = other", """theorem checked :
    AcceptedCollisionFree id (fun _ => true)
      (fun key : Bool => some (if key then (1 : Fin 3) else 0)) := by
  unfold AcceptedCollisionFree
  decide
""")
    add("accepted-initial-validity-waived", "AcceptedObserver",
        "(state.bad = false → AcceptedCollisionFree project accept state.cache)",
        "True", accepted_flag)

    pair_charge = theorem(src["AcceptedExamples"], "boolean_acceptance_charge_tight")
    history_charge = theorem(src["AcceptedExamples"], "accepted_history_charge_tight")
    add("accepted-charge-mass-omitted", "AcceptedCollision",
        "(trials.choose 2 : ℝ≥0∞) * mass", "(trials.choose 2 : ℝ≥0∞)", pair_charge)
    add("accepted-charge-pairs-omitted", "AcceptedCollision",
        "(trials.choose 2 : ℝ≥0∞) * mass", "0 * mass", pair_charge)
    add("accepted-charge-history-omitted", "AcceptedCollision",
        "(trials : ℝ≥0∞) * history", "(trials : ℝ≥0∞) * 0", history_charge)
    add("accepted-charge-size-shifted", "AcceptedCollision", ") / size", ") / (size + 1)", pair_charge)
    add("accepted-charge-mass-squared", "AcceptedCollision",
        "(trials.choose 2 : ℝ≥0∞) * mass", "(trials.choose 2 : ℝ≥0∞) * mass ^ 2", pair_charge)

    add("accepted-cache-preserving", "AcceptedObserver",
        "Function.update state.cache key (some value)",
        "Function.update state.cache key (some (id value))", accepted_query, True)
    add("accepted-seen-preserving", "AcceptedObserver",
        "insert (project value) state.seen", "insert (id (project value)) state.seen",
        accepted_valid, True)
    add("accepted-charge-mass-preserving", "AcceptedCollision",
        "(trials.choose 2 : ℝ≥0∞) * mass", "(trials.choose 2 : ℝ≥0∞) * (mass * 1)",
        pair_charge, True)
    add("accepted-charge-history-preserving", "AcceptedCollision",
        "(trials : ℝ≥0∞) * history", "(trials : ℝ≥0∞) * (0 + history)", history_charge, True)
    # Exact finite-word count: independent small enumerations and the unchanged
    # kernel computation consume the mutated definitions, including signed
    # residuals, row orientation, absent entries and the claimed decimal value.
    small_count = theorem(src["CountExamples"], "count_small_middle")
    add("count-radix-shifted", "WordCount", "Fintype.card (SumWords base digits target)",
        "Fintype.card (SumWords (base + 1) digits target)", small_count)
    add("count-length-shifted", "WordCount", "Fintype.card (SumWords base digits target)",
        "Fintype.card (SumWords base (digits + 1) target)", small_count)
    add("count-target-shifted", "WordCount", "Fintype.card (SumWords base digits target)",
        "Fintype.card (SumWords base digits (target + 1))", small_count)
    add("count-negative-clamped", "WordCount", "Fintype.card (SumWords base digits target)",
        "Fintype.card (SumWords base digits (target.toNat : ℤ))",
        theorem(src["CountExamples"], "count_negative_target"))
    add("count-sum-offset", "WordCount", "((word i).val : ℤ) = target}",
        "((word i).val : ℤ) = target + 1}",
        theorem(src["CountExamples"], "count_empty_zero"))

    step_window = theorem(src["CountExamples"], "count_step_window")
    vector_small = theorem(src["CountExamples"], "count_vector_small")
    basis_zero = theorem(src["CountExamples"], "count_basis_zero")
    basis_rep = theorem(src["CountVector"], "count_basis_rep")
    add("count-window-widened", "CountVector", "((value :: rest).take base).sum",
        "((value :: rest).take (base + 1)).sum", step_window)
    add("count-window-shifted", "CountVector", "((value :: rest).take base).sum",
        "(rest.take base).sum", step_window)
    add("count-window-unbounded", "CountVector", "((value :: rest).take base).sum",
        "(value :: rest).sum", step_window)
    add("count-row-tail-lost", "CountVector", ":: countStep base rest",
        ":: []", step_window)
    add("count-zero-steps-lost", "CountVector", "| 0, row => row",
        "| 0, _ => []", theorem(src["CountExamples"], "count_vector_zero_steps"))
    add("count-step-omitted", "CountVector", "countRun base digits (countStep base row)",
        "countRun base digits row", vector_small)
    add("count-step-duplicated", "CountVector", "countRun base digits (countStep base row)",
        "countRun base digits (countStep base (countStep base row))", vector_small)
    add("count-step-radix-ignored", "CountVector", "countRun base digits (countStep base row)",
        "countRun base digits (countStep 1 row)", vector_small)
    add("count-basis-length", "CountVector", "List.replicate target 0 ++ [1]",
        "List.replicate (target + 1) 0 ++ [1]", basis_zero)
    add("count-basis-zeroed", "CountVector", "List.replicate target 0 ++ [1]",
        "List.replicate target 0 ++ [0]", basis_zero)
    add("count-basis-reversed", "CountVector", "List.replicate target 0 ++ [1]",
        "[1] ++ List.replicate target 0", vector_small)
    add("count-representation-direction", "CountVector", "((target : ℤ) - i)",
        "((target : ℤ) + i)", basis_rep)
    add("count-representation-default", "CountVector", "row[i]?.getD 0",
        "row[i]?.getD 1", basis_rep)

    exact_count = theorem(src["WotsCount"], "wots_word_count_kernel")
    add("count-result-off-by-one", "WotsCount",
        "def wotsCountValue : ℕ := 22169393903687611906220091621190388",
        "def wotsCountValue : ℕ := 22169393903687611906220091621190389", exact_count)
    add("count-result-zeroed", "WotsCount",
        "def wotsCountValue : ℕ := 22169393903687611906220091621190388",
        "def wotsCountValue : ℕ := 0", exact_count)

    add("count-target-preserving", "WordCount", "Fintype.card (SumWords base digits target)",
        "Fintype.card (SumWords base digits (target + 0))", small_count, True)
    add("count-window-preserving", "CountVector", "((value :: rest).take base).sum",
        "(((value + 0) :: rest).take base).sum", step_window, True)
    add("count-basis-preserving", "CountVector", "List.replicate target 0 ++ [1]",
        "List.replicate target (0 + 0) ++ [1]", vector_small, True)
    add("count-result-preserving", "WotsCount",
        "def wotsCountValue : ℕ := 22169393903687611906220091621190388",
        "def wotsCountValue : ℕ := 22169393903687611906220091621190388 + 0", exact_count, True)
    # Fixed target hits in the actual cache. Concrete finite witnesses guard
    # the event and its initial-history boundary; projection consumers guard
    # the precise first16-byte node rather than a different zero predicate.
    target_one = theorem(src["TargetExamples"], "one_entry_no_target")
    target_live = theorem(src["TargetExamples"], "target_membership_nonvacuous")
    target_empty = theorem(src["TargetExamples"], "target_lookup_matters")
    add("target-predicate-inverted", "TargetEvent", "target value = false",
        "target value = true", target_one)
    add("target-predicate-waived", "TargetEvent", "target value = false",
        "True", target_live)
    add("target-lookup-omitted", "TargetEvent", "table key = some value → target value = false",
        "target value = false", target_empty)
    add("target-lookup-inverted", "TargetEvent", "table key = some value → target value = false",
        "table key ≠ some value → target value = false", target_one)
    add("target-universal-weakened", "TargetEvent", "∀ (key : K) (value : α), table key",
        "∃ (key : K) (value : α), table key", target_one)

    target_single = theorem(src["TargetExamples"], "fixed_target_singleton")
    add("target-set-inverted", "TargetSet", "decide (project value ∈ targets)",
        "decide (project value ∉ targets)", target_single)
    add("target-set-ignored", "TargetSet", "decide (project value ∈ targets)",
        "false", target_single)
    add("target-set-full", "TargetSet", "decide (project value ∈ targets)",
        "true", theorem(src["TargetExamples"], "fixed_target_empty"))

    node_projection = theorem(src["NodeZero"], "node_bytes_projection")
    add("node-low-half", "NodeZero", "⟨i.val, by omega⟩",
        "⟨i.val + 16, by omega⟩", node_projection)
    add("node-first-byte-repeated", "NodeZero", "⟨i.val, by omega⟩",
        "⟨0, by omega⟩", node_projection)
    add("node-last-byte-repeated", "NodeZero", "⟨i.val, by omega⟩",
        "⟨15, by omega⟩", node_projection)
    add("node-byte-order", "NodeZero", "⟨i.val, by omega⟩",
        "⟨15 - i.val, by omega⟩", node_projection)
    node_zero = local_consumer("NodeZero", "node_zero_iff",
        ["node_bytes_projection", "zero_randomizer_bytes"])
    add("node-whole-digest-zero", "NodeZero", "decide (nodeBytes digest = fun _ => 0)",
        "decide (digest = 0)", node_zero)
    add("node-any-byte-zero", "NodeZero", "decide (nodeBytes digest = fun _ => 0)",
        "decide (∃ i, nodeBytes digest i = 0)", node_zero)
    add("node-zero-replaced-one", "NodeZero", "decide (nodeBytes digest = fun _ => 0)",
        "decide (nodeBytes digest = fun _ => 1)", node_zero)
    node_event = theorem(src["NodeZero"], "public_node_zero_iff")
    add("node-event-cache-omitted", "NodeZero", "table key = some digest ∧ nodeZero digest = true",
        "nodeZero digest = true", node_event)
    add("node-event-target-inverted", "NodeZero", "table key = some digest ∧ nodeZero digest = true",
        "table key = some digest ∧ nodeZero digest = false", node_event)
    add("node-event-conjunction-lost", "NodeZero", "table key = some digest ∧ nodeZero digest = true",
        "table key = some digest ∨ nodeZero digest = true", node_event)
    node_union = "(¬ CollisionFree randomizerOfDigest table) ∨ PublicNodeZero table"
    add("node-union-zero-omitted", "NodeCharges", node_union,
        "¬ CollisionFree randomizerOfDigest table",
        theorem(src["TargetExamples"], "public_zero_alone_bad"))
    add("node-union-collision-omitted", "NodeCharges", node_union,
        "PublicNodeZero table", theorem(src["TargetExamples"], "public_collision_alone_bad"))

    add("target-predicate-preserving", "TargetEvent", "target value = false",
        "(target value || false) = false", target_one, True)
    add("target-set-preserving", "TargetSet", "decide (project value ∈ targets)",
        "decide (project value ∈ targets ∪ ∅)", target_single, True)
    add("node-byte-index-preserving", "NodeZero", "⟨i.val, by omega⟩",
        "⟨i.val + 0, by omega⟩", node_projection, True)
    add("node-zero-value-preserving", "NodeZero", "decide (nodeBytes digest = fun _ => 0)",
        "decide (nodeBytes digest = fun _ => (0 + 0))", node_zero, True)

    # Selected-domain accounting keeps the full execution/cache. Definition
    # fixtures and unchanged finite consumers distinguish erasure, observer,
    # structural budget and exact byte-selector failures.
    selected_membership = theorem(src["DomainExamples"], "selected_cache_membership")
    selected_cache = "if select key then table key else none"
    add("selected-cache-inverted", "SelectedObserver", selected_cache,
        "if select key then none else table key", selected_membership)
    add("selected-cache-erased", "SelectedObserver", selected_cache,
        "none", selected_membership)
    add("selected-view-unfiltered", "SelectedObserver",
        "⟨selectedCache select state.cache, state.seen, state.bad⟩",
        "⟨state.cache, state.seen, state.bad⟩",
        theorem(src["DomainExamples"], "excluded_prior_history_valid"))
    excluded_record = "else ⟨Function.update state.cache key (some value), state.seen, state.bad⟩"
    stored = theorem(src["DomainExamples"], "excluded_reply_stored")
    add("excluded-reply-forgotten", "SelectedObserver", excluded_record,
        "else ⟨state.cache, state.seen, state.bad⟩", stored)
    add("excluded-reply-inserted", "SelectedObserver", excluded_record,
        "else ⟨Function.update state.cache key (some value), insert (project value) state.seen, state.bad⟩",
        stored)
    add("excluded-prior-flag-cleared", "SelectedObserver", excluded_record,
        "else ⟨Function.update state.cache key (some value), state.seen, false⟩",
        theorem(src["DomainExamples"], "selected_prior_flag"))
    selected_record = "if select key then recordReply project state key value"
    add("selected-record-inverted", "SelectedObserver", selected_record,
        "if !select key then recordReply project state key value", stored)
    add("selected-flag-cleared", "SelectedObserver", selected_record,
        "if select key then { recordReply project state key value with bad := false }",
        theorem(src["DomainExamples"], "selected_reply_collision"))
    add("selected-seen-omitted", "SelectedObserver", selected_record,
        "if select key then { recordReply project state key value with seen := state.seen }",
        theorem(src["DomainExamples"], "selected_reply_seen"))
    add("excluded-cached-resampled", "SelectedObserver", "| some value => PMF.pure (value, state)",
        "| some value => p.map (fun fresh => (fresh, state))",
        theorem(src["DomainExamples"], "excluded_cached_reply"))

    repeats = theorem(src["DomainExamples"], "selected_budget_counts_repeats")
    add("selected-budget-not-consumed", "SelectedBudget", "(next reply) (q - 1)",
        "(next reply) q", repeats)
    add("selected-budget-zero-waived", "SelectedBudget", "0 < q ∧", "True ∧", repeats)
    add("selected-budget-one-branch", "SelectedBudget",
        "else ∀ reply, SelectedBudget select (next reply) q",
        "else ∃ reply, SelectedBudget select (next reply) q",
        theorem(src["DomainExamples"], "selected_budget_all_branches"))
    add("excluded-call-spends-selected-budget", "SelectedBudget",
        "else ∀ reply, SelectedBudget select (next reply) q",
        "else ∀ reply, SelectedBudget select (next reply) (q - 1)",
        """theorem checked :
    SelectedBudget id (.query false (fun _ : Bool => .query true
      (fun _ => .done (n := 0) ()))) 1 := by
  simp [SelectedBudget]
""")

    count_domain = theorem(src["DomainExamples"], "node_domain_count_zero_kind")
    hmsg_domain = theorem(src["DomainExamples"], "node_domain_hmsg_width")
    kind_first = theorem(src["DomainExamples"], "node_domain_kind_first_byte")
    kind_last = theorem(src["DomainExamples"], "node_domain_kind_last_byte")
    add("domain-hmsg-width-shifted", "NodeDomain", "key.length ≠ 160", "key.length ≠ 159", hmsg_domain)
    add("domain-count-width-shifted", "NodeDomain", "key.length ≠ 128", "key.length ≠ 127", count_domain)
    add("domain-hmsg-conjunction-lost", "NodeDomain", "key.length ≠ 160 ∧",
        "key.length ≠ 160 ∨", hmsg_domain)
    add("domain-pair-width-excluded", "NodeDomain", "key.length ≠ 128 ∨",
        "key.length ≠ 128 ∧", kind_last)
    add("domain-kind-start-early", "NodeDomain", "key.drop 44", "key.drop 43", kind_last)
    add("domain-kind-start-late", "NodeDomain", "key.drop 44", "key.drop 45", kind_first)
    add("domain-kind-shortened", "NodeDomain", ").take 4", ").take 3", count_domain)
    add("domain-kind-widened", "NodeDomain", ").take 4", ").take 5", count_domain)
    add("domain-kind-nonzero-excluded", "NodeDomain", "List.replicate 4 0",
        "List.replicate 4 1", count_domain)

    domain_union = "(¬ CollisionFree randomizerOfDigest (selectedCache nodeQuery table)) ∨ PublicNodeZero table"
    add("domain-union-zero-omitted", "DomainNodeCharges", domain_union,
        "¬ CollisionFree randomizerOfDigest (selectedCache nodeQuery table)",
        theorem(src["DomainExamples"], "domain_zero_from_excluded"))
    add("domain-union-collision-omitted", "DomainNodeCharges", domain_union,
        "PublicNodeZero table", theorem(src["DomainExamples"], "domain_collision_alone_bad"))

    add("selected-cache-preserving", "SelectedObserver", selected_cache,
        "if select key || false then table key else none", selected_membership, True)
    add("selected-budget-preserving", "SelectedBudget", "0 < q ∧", "0 + 0 < q ∧", repeats, True)
    add("domain-kind-offset-preserving", "NodeDomain", "key.drop 44", "key.drop (40 + 4)", kind_last, True)
    add("domain-kind-zero-preserving", "NodeDomain", "List.replicate 4 0",
        "List.replicate 4 (0 + 0)", count_domain, True)
    # Exact WOTS count/chain clients: compare typed definitions with unchanged
    # finite executions and byte vectors, retaining cache and failure behavior.
    def wots_example(name):
        return theorem(src["WotsProgramExamples"], name)

    add("count-client-accept-inverted", "CountProgram", "if accept reply then",
        "if !accept reply then", wots_example("count_early_cache"))
    add("count-client-success-counter", "CountProgram", ".done (some (start, reply))",
        ".done (some (start + 1, reply))", wots_example("count_early_cache"))
    add("count-client-result-lost", "CountProgram", ".done (some (start, reply))",
        ".done none", wots_example("count_early_cache"))
    add("count-client-retry-counter", "CountProgram", "countProgram accept (start + 1) keys",
        "countProgram accept start keys", wots_example("count_cached_advances"))
    add("count-client-premature-exhaustion", "CountProgram", "else countProgram accept (start + 1) keys",
        "else .done none", wots_example("count_cached_advances"))

    chain_step = "chainProgram input project (start + 1) steps (project reply)"
    add("chain-client-projection-lost", "ChainProgram", chain_step,
        "chainProgram input project (start + 1) steps current", wots_example("chain_projection_used"))
    add("chain-client-position-not-advanced", "ChainProgram", chain_step,
        "chainProgram input project start steps (project reply)", wots_example("chain_positions_advance"))
    add("chain-client-first-position-shifted", "ChainProgram", ".query (input start current)",
        ".query (input (start + 1) current)", wots_example("chain_positions_advance"))
    add("chain-client-shortened", "ChainProgram", chain_step,
        ".done (project reply)", wots_example("chain_positions_advance"))

    loop_store = """theorem checked :
    chainLoop (PMF.pure true) (fun pos (_ : Bool) => pos) id 2 1 false
      (fun _ : ℕ => none) =
      PMF.pure (true, Function.update (fun _ => none) 2 (some true)) := by
  simp [chainLoop, memoQuery, PMF.pure_map, PMF.pure_bind]
"""
    add("chain-loop-store-lost", "ChainProgram", "steps (project reply.1) reply.2",
        "steps (project reply.1) table", loop_store)
    add("chain-loop-reply-lost", "ChainProgram", "steps (project reply.1) reply.2",
        "steps current reply.2", loop_store)
    add("chain-loop-zero-cache-lost", "ChainProgram", "PMF.pure (current, table)",
        "PMF.pure (current, fun _ => none)", """theorem checked :
    chainLoop fairReply (fun _ (value : Bool) => value) id 3 0 true (fun _ => some false) =
      PMF.pure (true, fun _ => some false) := by rfl
""")

    address_vector = wots_example("address_field_endianness")
    add("address-byte-order-reversed", "AddressBytes", "width - 1 - i.val", "i.val", address_vector)
    add("address-tree-width-shortened", "AddressBytes", "beBytes 8 tree", "beBytes 4 tree", address_vector)
    add("address-kind-and-keypair-swapped", "AddressBytes", "beBytes 4 kind ++ beBytes 4 kp",
        "beBytes 4 kp ++ beBytes 4 kind", address_vector)
    add("address-position-and-hash-swapped", "AddressBytes", "beBytes 4 position ++ beBytes 4 hashAddress",
        "beBytes 4 hashAddress ++ beBytes 4 position", address_vector)

    add("wots-count-kind-changed", "WotsProgram", "c10Address layer tree 0 kp 0 0 0",
        "c10Address layer tree 1 kp 0 0 0", wots_example("wots_count_valid_excluded"))
    add("wots-count-padding-changed", "WotsProgram", "message ++ List.replicate 16 0",
        "message ++ List.replicate 16 1", wots_example("wots_count_message_padding"))
    add("wots-count-index-changed", "WotsProgram", "c10Address layer tree 0 kp 0 0 0",
        "c10Address layer tree 0 kp 1 0 0", theorem(src["WotsProgram"], "wots_count_key_layout"))
    count_compile = theorem(src["WotsProgram"], "wots_count_program_eval")
    add("wots-count-client-counter-shifted", "WotsProgram",
        "countProgram (wotsAccept ∘ wotsOfDigest) start",
        "countProgram (wotsAccept ∘ wotsOfDigest) (start + 1)", count_compile)
    add("wots-count-search-history-lost", "WotsProgram",
        "memoGrind digestDraw (wotsAccept ∘ wotsOfDigest) table start",
        "memoGrind digestDraw (wotsAccept ∘ wotsOfDigest) (fun _ => none) start", count_compile)
    add("wots-count-search-acceptance-lost", "WotsProgram",
        "memoGrind digestDraw (wotsAccept ∘ wotsOfDigest) table start",
        "memoGrind digestDraw (fun _ => true) table start", """theorem checked :
    wotsCountSearch (fun _ => some 0) (List.replicate 32 0) 0 0 0
      (List.replicate 16 0) 7 1 (by decide) = PMF.pure (none, fun _ => some 0) := by
  have rejected : wotsAccept (wotsOfDigest 0) = false := by decide +kernel
  unfold wotsCountSearch counterSchedule
  rw [List.ofFn_succ]
  simp only [List.ofFn_zero]
  rw [memoGrind]
  rw [memoQuery_cached digestDraw (fun _ => some 0) _ 0 rfl, PMF.pure_bind]
  simp only [Function.comp_apply, Prod.fst, Prod.snd]
  rw [rejected]
  rfl
""")

    add("wots-chain-node-lost", "WotsChain", "randomizerBytesEquiv.symm current",
        "randomizerBytesEquiv.symm 0", wots_example("wots_chain_node_and_padding"))
    add("wots-chain-address-fields-swapped", "WotsChain",
        "c10Address layer tree 0 kp index position 0",
        "c10Address layer tree 0 kp position index 0", wots_example("wots_chain_address_offsets"))

    add("count-client-counter-preserving", "CountProgram", "countProgram accept (start + 1) keys",
        "countProgram accept (1 + start) keys", wots_example("count_cached_advances"), True)
    add("chain-client-position-preserving", "ChainProgram", chain_step,
        "chainProgram input project (1 + start) steps (project reply)",
        wots_example("chain_positions_advance"), True)
    add("address-byte-index-preserving", "AddressBytes", "width - 1 - i.val",
        "width - (i.val + 1)", address_vector, True)
    add("wots-count-padding-preserving", "WotsProgram", "message ++ List.replicate 16 0",
        "message ++ List.replicate 16 (0 + 0)", wots_example("wots_count_message_padding"), True)
    return out
