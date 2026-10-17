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
    # Complete recovery: ordered collection, exact accepted-word work,
    # compression bytes and both recovery continuations through the full cache.
    def recovery_example(name):
        return theorem(src["WotsRecoveryExamples"], name)

    src["CollectionStepCount"] = (src["ChainCollection"].split("def mapReturnProgram", 1)[0] +
        "def collectionSteps" + src["ChainCollection"].split("def collectionSteps", 1)[1].split(
            "def chainCollectionProgram", 1)[0] + "end\nend C10Probability\n")
    add("collection-raw-step-sum", "CollectionStepCount", "(indices.map steps).sum",
        "(indices.map steps).length", recovery_example("collection_step_sum"))
    add("collection-loop-order", "ChainCollection", "current.1 :: later.1",
        "later.1 ++ [current.1]", recovery_example("collection_zero_order"))
    add("collection-loop-return-lost", "ChainCollection", "current.1 :: later.1",
        "values i :: later.1", recovery_example("collection_cached_order"))
    add("collection-loop-history-lost", "ChainCollection", "values rest current.2",
        "values rest table", recovery_example("collection_accumulates_cache"))
    add("collection-loop-final-cache-lost", "ChainCollection", "current.1 :: later.1, later.2",
        "current.1 :: later.1, table", recovery_example("collection_accumulates_cache"))
    program_order = recovery_example("collection_program_zero_order")
    map_helper = theorem(src["ChainCollection"], "evalProgram_mapReturn").replace(
        "theorem checked", "have evalProgram_mapReturn {K α R T : Type}", 1)
    program_order = program_order.replace(":= by\n", ":= by\n" +
        "\n".join("  " + line for line in map_helper.splitlines()) + "\n", 1)
    add("collection-program-order", "ChainCollection", "(List.cons current)",
        "(fun later => later ++ [current])", program_order)
    add("collection-loop-project-lost", "ChainCollection", "(starts i) (steps i) (values i) table",
        "(starts i) 0 (values i) table", recovery_example("collection_cached_order"))

    # The dependent client index enforces the arithmetic in the normal build.
    # Isolate the actual index and work-count definitions here so a changed
    # count remains well typed and is rejected at its numerical consumer.
    src["WotsRemainingCore"] = src["WotsRemaining"].split("theorem wots_indices_length", 1)[0] + \
        "end\nend C10Probability\n"
    add("recovery-index-reversed", "WotsRemainingCore", "List.ofFn id",
        "(List.ofFn id).reverse", recovery_example("wots_index_order"))
    add("recovery-remaining-off-by-one", "WotsRemainingCore",
        "collectionSteps (fun i => 7 - (word i).val)",
        "collectionSteps (fun i => 8 - (word i).val)", recovery_example("wots_remaining_max_word"))
    add("recovery-remaining-uses-digit", "WotsRemainingCore",
        "collectionSteps (fun i => 7 - (word i).val)",
        "collectionSteps (fun i => (word i).val)", recovery_example("wots_remaining_zero_word"))

    add("compression-node-padding", "WotsCompression", "List.replicate 16 0",
        "List.replicate 16 1", recovery_example("compression_node_bytes"))
    add("compression-node-value", "WotsCompression", "randomizerBytesEquiv.symm value",
        "randomizerBytesEquiv.symm 0", recovery_example("compression_node_bytes"))
    add("compression-kind-zero", "WotsCompression", "c10Address layer tree 1 kp 0 0 0",
        "c10Address layer tree 0 kp 0 0 0", recovery_example("compression_kind_bytes"))
    add("compression-elements-reversed", "WotsCompression", "values.flatMap nodeBlock",
        "values.reverse.flatMap nodeBlock", recovery_example("compression_element_order"))
    add("compression-result-zeroed", "WotsCompression", "(randomizerOfDigest reply.1, reply.2)",
        "(0, reply.2)", recovery_example("compression_result_cache"))
    add("compression-cache-erased", "WotsCompression", "(randomizerOfDigest reply.1, reply.2)",
        "(randomizerOfDigest reply.1, fun _ => none)", recovery_example("compression_result_cache"))

    add("recovery-rejected-node-changed", "WotsRecovery", "else PMF.pure (0, counted.2)",
        "else PMF.pure (1, counted.2)", recovery_example("recovery_invalid_retains_cache"))
    add("recovery-rejected-cache-erased", "WotsRecovery", "else PMF.pure (0, counted.2)",
        "else PMF.pure (0, fun _ => none)", recovery_example("recovery_invalid_retains_cache"))
    add("recovery-client-fallback-changed", "WotsRecovery", "else .done 0",
        "else .done 1", recovery_example("recovery_after_rejected"))
    # An accepted cached execution consumes the actual branch and all chains.
    # The comparison retains the complete cache, with no fresh-draw premise.
    accepted_recovery = """theorem checked (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (nonce : Counter) (digest : Digest)
    (ha : wotsAccept (wotsOfDigest digest) = true) :
    wotsRecovery (fun _ => some digest) seed layer tree kp message
      (fun _ => randomizerOfDigest digest) nonce =
      PMF.pure (randomizerOfDigest digest, fun _ => some digest) := by
  simp only [wotsRecovery, memoQuery, PMF.pure_bind]
  rw [ha]
  simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
  rw [wotsRecoverChains, chainCollectionLoop_constant_cached, PMF.pure_bind]
  exact wots_compress_cached _ _ _ _ _ _ digest rfl
"""
    add("recovery-acceptance-inverted", "WotsRecovery", "if wotsAccept (wotsOfDigest counted.1) then",
        "if !wotsAccept (wotsOfDigest counted.1) then", accepted_recovery)
    add("recovery-chain-cache-reset", "WotsRecovery", "wotsRecoverChains counted.2 seed",
        "wotsRecoverChains (fun _ => none) seed", accepted_recovery)
    add("recovery-count-cache-reset", "WotsRecovery", "memoQuery digestDraw table (counterKey",
        "memoQuery digestDraw (fun _ => none) (counterKey", accepted_recovery)
    add("recovery-client-accepted-skipped", "WotsRecovery",
        """bindProgram (wotsAcceptedChainsProgram seed layer tree kp (wotsOfDigest digest) ha sigma)
      (fun values => wotsCompressProgram seed layer tree kp values)""",
        ".done 0", theorem(src["WotsRecovery"], "wots_recovery_after_eval"))

    add("collection-order-preserving", "ChainCollection", "current.1 :: later.1",
        "[current.1] ++ later.1", recovery_example("collection_cached_order"), True)
    add("recovery-remaining-preserving", "WotsRemainingCore",
        "collectionSteps (fun i => 7 - (word i).val)",
        "collectionSteps (fun i => (3 + 4) - (word i).val)",
        recovery_example("wots_remaining_accepted_word"), True)
    add("compression-padding-preserving", "WotsCompression", "List.replicate 16 0",
        "List.replicate 16 (0 + 0)", recovery_example("compression_node_bytes"), True)
    add("recovery-fallback-preserving", "WotsRecovery", "else PMF.pure (0, counted.2)",
        "else PMF.pure (0, (fun out => out.2) counted)", recovery_example("recovery_invalid_retains_cache"), True)
    # Full WOTS signing: source-derived definition slices retain the actual
    # computations while omitting proof-index casts from mutation fixtures.
    def signer_example(name):
        return "set_option maxRecDepth 4096\n" + theorem(src["WotsSignerExamples"], name)

    def signer_decl(module, name):
        match = re.search(r"^(?:def|abbrev) " + re.escape(name) +
                          r"\b.*?(?=^(?:theorem|def|abbrev|end|attribute)\b)",
                          src[module], flags=re.M | re.S)
        if not match:
            raise ValueError("missing signer definition " + name)
        return match.group(0).split("\n/--", 1)[0]

    src["WotsShufflePure"] = src["WotsShuffle"].split("abbrev WotsOrder", 1)[0] + \
        "end\nend C10Probability\n"
    src["WotsShuffleBlocks"] = (
        "import C10Probability.WotsPrivate\nnamespace C10Probability\nnoncomputable section\n"
        "variable {K : Type*}\n" +
        "\n".join(signer_decl("WotsShuffle", name) for name in
                  ["fisherTag", "shuffleBlockInput", "shuffleBlocksProgram", "shuffleBlocks"]) +
        "end\nend C10Probability\n")
    src["WotsSignDirect"] = (
        "import C10Probability.WotsLeaf\nimport C10Probability.WotsShuffle\n"
        "import C10Probability.WotsProgram\nimport C10Probability.WotsRecoveryExamples\n"
        "namespace C10Probability\nnoncomputable section\nvariable {K : Type*}\n" +
        "\n".join(signer_decl("WotsSigning", name) for name in
                  ["wotsCountUnder", "WotsSignature", "wotsSignAfter", "wotsSign"]) +
        "end\nend C10Probability\n")
    cached_helpers = "set_option maxRecDepth 4096\n" + "\n".join(
        theorem(src["WotsSignerExamples"], name).replace("theorem checked", "theorem " + name, 1)
        for name in ["wots_seed_chain_cached", "wots_fill_cached", "wots_constant_writes",
                     "wots_fill_cached_complete", "memoGrind_cached_reject", "memoGrind_cached_accept"])
    accepted_case = cached_helpers + signer_example("wots_sign_one_accepted_cached")
    rejected_case = cached_helpers + signer_example("wots_sign_one_rejected")

    add("state-fold-return-discarded", "StateFold", "rest out.1 out.2", "rest state out.2",
        signer_example("state_fold_order"))
    add("state-fold-cache-reset", "StateFold", "rest out.1 out.2", "rest out.1 table",
        signer_example("state_fold_accumulated_cache"))
    add("state-fold-visit-dropped", "StateFold", "stateFoldLoop p cost step rest out.1 out.2",
        "PMF.pure out", signer_example("state_fold_order"))

    add("wots-private-tag", "WotsPrivate", "[119, 111, 116, 115]", "[119, 111, 116, 116]",
        signer_example("wots_private_byte_vector"))
    add("wots-private-tree-width", "WotsPrivate", "beBytes 32 tree", "beBytes 8 tree",
        signer_example("wots_private_byte_vector"))
    add("wots-private-layer-width", "WotsPrivate", "beBytes 4 layer", "beBytes 8 layer",
        signer_example("wots_private_byte_vector"))
    add("wots-private-kp-index-order", "WotsPrivate", "beBytes 4 kp ++ beBytes 4 index",
        "beBytes 4 index ++ beBytes 4 kp", signer_example("wots_private_byte_vector"))
    add("wots-private-public-route", "WotsPrivate",
        "memoQuery digestDraw table (encode (.inr (wotsPrivateTail layer tree kp index)))",
        "memoQuery digestDraw table (encode (.inl (wotsPrivateTail layer tree kp index)))",
        signer_example("wots_private_query_route"))
    add("wots-private-node-zero", "WotsPrivate",
        "0 steps (randomizerOfDigest reply.1) reply.2", "0 steps 0 reply.2",
        signer_example("wots_fill_single_position"))
    add("wots-fill-wrong-position", "WotsPrivate",
        "(Function.update sigma i out.1) out.2", "(Function.update sigma 0 out.1) out.2",
        signer_example("wots_fill_single_position"))
    add("wots-fill-return-lost", "WotsPrivate",
        "(Function.update sigma i out.1) out.2", "sigma out.2",
        signer_example("wots_fill_single_position"))
    add("wots-fill-cache-erased", "WotsPrivate", "| [], sigma, table => PMF.pure (sigma, table)",
        "| [], sigma, table => PMF.pure (sigma, fun _ => none)",
        signer_example("wots_fill_single_position"))

    add("wots-shuffle-tag", "WotsShufflePure",
        "[115,112,104,105,110,99,115,45,99,49,48,45,102,105,115,104,101,114,45,121,97,116,101,115,45,118,49]",
        "[115,112,104,105,110,99,115,45,99,49,48,45,102,105,115,104,101,114,45,121,97,116,101,115,45,118,50]",
        "theorem checked : fisherTag[26]? = some 49 := by decide +kernel\n")
    add("wots-shuffle-counter-endian", "WotsShufflePure", "beBytes 4 block",
        "(beBytes 4 block).reverse", signer_example("shuffle_block_counter_vector"))
    add("wots-shuffle-pair-endian", "WotsShufflePure",
        "((stream[pos + 1]?).getD 0).val * 256 + ((stream[pos]?).getD 0).val",
        "((stream[pos]?).getD 0).val * 256 + ((stream[pos + 1]?).getD 0).val",
        signer_example("shuffle_pair_little_endian"))
    add("wots-shuffle-multiply-high-divisor", "WotsShufflePure", "/ 65536", "/ 65535",
        signer_example("shuffle_multiply_high_not_modulo"))
    add("wots-shuffle-modulo-replacement", "WotsShufflePure",
        "* (i + 1) / 65536", "% (i + 1)", signer_example("shuffle_pair_little_endian"))
    add("wots-shuffle-second-write", "WotsShufflePure",
        ".set j ((order[i]?).getD 0)", ".set i ((order[i]?).getD 0)",
        signer_example("shuffle_swap_positions"))
    add("wots-shuffle-stream-stride", "WotsShufflePure",
        "shuffleLoop stream i (pos + 2)", "shuffleLoop stream i (pos + 1)",
        signer_example("shuffle_patterned_order"))
    add("wots-shuffle-visit-index", "WotsShufflePure",
        "shuffleSwap order (i + 1) (shuffleChoice stream pos (i + 1))",
        "shuffleSwap order i (shuffleChoice stream pos i)", signer_example("shuffle_patterned_order"))

    # The count and shuffle effects are retained as their actual PMF calls in
    # these complete-procedure equations, so history/reset mutations are tested
    # without enumerating the256-bit uniform sample space.
    sign_equation = """theorem checked [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree kp : ℕ) (message shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) :
    wotsSign encode table seed layer tree kp message shuffle n hb =
      (wotsCountUnder (fun key => encode (.inl key)) table seed layer tree kp message n hb).bind
        (fun out => wotsSignAfter encode out.2 seed layer tree kp shuffle out.1) := by rfl
"""
    after_equation = """theorem checked [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree kp : ℕ) (shuffle : ByteKey)
    (count : ℕ) (digest : Digest) :
    wotsSignAfter encode table seed layer tree kp shuffle (some (count,digest)) =
      (wotsShuffle (fun key => encode (.inl key)) shuffle table).bind (fun order =>
        (wotsFillLoop encode seed layer tree kp (fun i => (wotsOfDigest digest i).val)
          order.1.val wotsZeroSigma order.2).map (fun out => (some (out.1,count),out.2))) := by rfl
"""
    add("wots-sign-exhaustion-emits", "WotsSignDirect", "| none => PMF.pure (none, table)",
        "| none => PMF.pure (some (wotsZeroSigma,0), table)", signer_example("wots_sign_no_trials"))
    add("wots-sign-exhaustion-cache-lost", "WotsSignDirect", "| none => PMF.pure (none, table)",
        "| none => PMF.pure (none, fun _ => none)", rejected_case)
    add("wots-sign-counter-changed", "WotsSignDirect", "(some (out.1, count), out.2)",
        "(some (out.1, count + 1), out.2)", accepted_case)
    add("wots-sign-success-cache-lost", "WotsSignDirect", "(some (out.1, count), out.2)",
        "(some (out.1, count), fun _ => none)", accepted_case)
    add("wots-sign-count-history-reset", "WotsSignDirect", "wotsSignAfter encode out.2 seed",
        "wotsSignAfter encode table seed", sign_equation)
    add("wots-sign-shuffle-history-reset", "WotsSignDirect", "order.1.val wotsZeroSigma order.2",
        "order.1.val wotsZeroSigma table", after_equation)
    add("wots-sign-shuffle-order-discarded", "WotsSignDirect", "order.1.val wotsZeroSigma order.2",
        "wotsIndices wotsZeroSigma order.2", after_equation)
    add("wots-sign-chain-length-changed", "WotsSignDirect", "(fun i => (wotsOfDigest digest i).val)",
        "(fun i => 7 - (wotsOfDigest digest i).val)", after_equation)

    add("wots-private-tag-preserving", "WotsPrivate", "[119, 111, 116, 115]",
        "[119, 111, 116, 114 + 1]", signer_example("wots_private_byte_vector"), True)
    add("wots-shuffle-stride-preserving", "WotsShufflePure", "shuffleLoop stream i (pos + 2)",
        "shuffleLoop stream i (pos + (1 + 1))", signer_example("shuffle_patterned_order"), True)
    add("wots-sign-exhaustion-preserving", "WotsSignDirect", "| none => PMF.pure (none, table)",
        "| none => PMF.pure ((none : WotsSignature), table)", signer_example("wots_sign_no_trials"), True)
    # Alias only the definition under test so proof-dependent return types
    # can be imported without redeclaring their checked permutation proofs.
    src["WotsShuffleProgramAlias"] = (
        "import C10Probability.WotsShuffle\nnamespace C10Probability\nnoncomputable section\n"
        "variable {K : Type*}\n" + signer_decl("WotsShuffle", "wotsShuffleProgram").replace(
            "def wotsShuffleProgram ", "def wotsShuffleCandidate ", 1) +
        "end\nend C10Probability\n")
    src["WotsShuffleBlocksAlias"] = (
        "import C10Probability.WotsShuffle\nnamespace C10Probability\nnoncomputable section\n"
        "variable {K : Type*}\n" + signer_decl("WotsShuffle", "shuffleBlocksProgram").replace(
            "shuffleBlocksProgram", "shuffleBlocksCandidate") +
        signer_decl("WotsShuffle", "wotsShuffleProgram").replace(
            "def wotsShuffleProgram ", "def wotsShuffleCandidate ", 1).replace(
            "shuffleBlocksProgram", "shuffleBlocksCandidate") +
        "end\nend C10Probability\n")
    query_case = signer_example("shuffle_query_order").replace("wotsShuffleProgram", "wotsShuffleCandidate")
    block_case = query_case.replace("shuffleBlocksProgram", "shuffleBlocksCandidate")
    add("wots-shuffle-fourth-call-missing", "WotsShuffleProgramAlias",
        "(shuffleBlocksProgram encode seed 0 4)",
        "(reserveProgram 1 (shuffleBlocksProgram encode seed 0 3))", query_case)
    add("wots-shuffle-zero-seed-query", "WotsShuffleProgramAlias",
        "if seed = List.replicate 32 0 then", "if seed = [] then",
        signer_example("shuffle_zero_query_trace").replace("wotsShuffleProgram", "wotsShuffleCandidate"))
    add("wots-shuffle-block-counter-repeated", "WotsShuffleBlocksAlias",
        "shuffleBlocksCandidate encode seed (start + 1) n", "shuffleBlocksCandidate encode seed start n",
        block_case)
    add("wots-shuffle-four-calls-preserving", "WotsShuffleProgramAlias",
        "(shuffleBlocksProgram encode seed 0 4)",
        "(shuffleBlocksProgram encode seed 0 (2 + 2))", query_case, True)
    # Merkle subtree controls: full source-derived pure/direct procedures and
    # finite observable traces. Indexed compiler definitions keep their proved
    # cost transports; mutations must typecheck before a consumer can count.
    def merkle_example(name):
        return "set_option maxRecDepth 20000\n" + theorem(src["MerkleExamples"], name)

    def merkle_decl(module, name):
        match = re.search(r"^(?:def|abbrev|structure) " + re.escape(name) +
                          r"\b.*?(?=^(?:theorem|def|abbrev|structure|end|attribute)\b)",
                          src[module], flags=re.M | re.S)
        if not match:
            raise ValueError("missing Merkle definition " + name)
        return match.group(0).split("\n/--", 1)[0]

    def merkle_slice(name, imports, declarations, variables=""):
        src[name] = ("".join("import C10Probability." + mod + "\n" for mod in imports) +
            "namespace C10Probability\nnoncomputable section\n" + variables + "\n" +
            "\n".join(merkle_decl(mod, decl) for mod, decl in declarations) +
            "end\nend C10Probability\n")

    merkle_slice("MerkleShapePure", ["StateFold"],
        [("TreeShape", name) for name in ["MergeShape", "mergeShape", "nextShape", "runShape", "shapeCalls", "treeCalls"]])
    merkle_slice("MerkleKeepPure", ["MerkleInputs"],
        [("MerkleBuild", name) for name in ["AuthKeep", "emptyAuthKeep", "writeAuthKeep", "authRemember"]])
    merkle_slice("MerkleMergeDirect", ["TreeShape"],
        [("TreeMerge", "mergeLoop"), ("MerkleExamples", "treeExampleInput")],
        "variable {K α N S : Type*}")
    merkle_slice("MerkleTreeDirect", ["TreeMerge"],
        [("TreeRun", "treeLoop"), ("MerkleExamples", "treeExampleInput")],
        "variable {K α N S : Type*}")
    merkle_slice("MerkleTreeCompiler", ["TreeMerge"],
        [("TreeRun", "treeProgram"), ("MerkleExamples", "treeExampleInput")],
        "variable {K α N S : Type*}")
    merkle_slice("MerkleRecoveryDirect", ["MerkleInputs"],
        [("MerkleRecover", name) for name in ["recoveryInput", "recoveryLoop", "merkleRecover"]],
        "variable {K : Type*}")
    merkle_slice("MerkleRecoveryCompiler", ["MerkleInputs"],
        [("MerkleRecover", name) for name in ["recoveryInput", "recoveryProgram", "merkleRecoverProgram"]],
        "variable {K : Type*}")

    shape = merkle_example("tree_shape_frontier")
    add("tree-shape-unequal-merge", "MerkleShapePure", "if level = height then",
        "if height ≤ level then", shape)
    add("tree-shape-height-jump", "MerkleShapePure", "mergeShape (height + 1) rest",
        "mergeShape (height + 2) rest", shape)
    add("tree-shape-double-charge", "MerkleShapePure", "next.calls + 1", "next.calls + 2", shape)
    add("tree-shape-push-lost", "MerkleShapePure", "out.height :: out.rest", "out.rest", shape)
    add("tree-leaf-charge-lost", "MerkleShapePure", "leafCalls * n + shapeCalls n stack",
        "leafCalls * (n - 1) + shapeCalls n stack",
        "set_option maxRecDepth 20000\ntheorem checked : treeCalls 345 512 [] = 177151 := by decide +kernel\n")

    pair = merkle_example("merkle_pair_byte_vector")
    add("merkle-pair-kind", "MerkleInputs", "c10Address layer tree 2 0 0", "c10Address layer tree 1 0 0", pair)
    add("merkle-pair-height", "MerkleInputs", "(height + 1) parent", "height parent", pair)
    add("merkle-pair-order", "MerkleInputs", "nodeBlock left ++ nodeBlock right",
        "nodeBlock right ++ nodeBlock left", pair)
    add("merkle-pair-child-duplicated", "MerkleInputs", "nodeBlock left ++ nodeBlock right",
        "nodeBlock left ++ nodeBlock left", pair)
    add("merkle-pair-parent-level", "MerkleInputs", "(kp / 2 ^ (height + 1))",
        "(kp / 2 ^ height)", merkle_example("tree_pair_parent_vector"))
    add("merkle-sibling-parity", "MerkleInputs", "if index % 2 = 0 then index + 1 else index - 1",
        "if index % 2 = 0 then index - 1 else index + 1", merkle_example("sibling_index_vector"))
    add("merkle-root-default", "MerkleInputs", "stack.headD (0, 0)", "stack.headD (1, 0)",
        merkle_example("tree_root_default_vector"))

    add("merkle-keep-left-child", "MerkleKeepPure", "then writeAuthKeep state height left",
        "then writeAuthKeep state height right", merkle_example("auth_remember_left_vector"))
    add("merkle-keep-right-child", "MerkleKeepPure", "then writeAuthKeep state height right",
        "then writeAuthKeep state height left", merkle_example("auth_remember_right_vector"))
    add("merkle-keep-height-slot", "MerkleKeepPure", "state.nodes.set height node",
        "state.nodes.set (height + 1) node", merkle_example("auth_remember_high_vector"))
    add("merkle-keep-flag", "MerkleKeepPure", "state.kept.set height true",
        "state.kept.set height false", merkle_example("auth_remember_left_vector"))
    add("merkle-keep-rewrites", "MerkleKeepPure", "if (state.kept[height]?).getD false then state",
        "if false then state", merkle_example("auth_remember_once_vector"))
    add("merkle-keep-left-coordinate", "MerkleKeepPure", "let leftIndex := pairStart / 2 ^ height",
        "let leftIndex := kp / 2 ^ height", merkle_example("auth_remember_left_vector"))
    add("merkle-keep-nonsibling", "MerkleKeepPure", "else if leftIndex + 1 = sibling then",
        "else if true then", merkle_example("auth_remember_irrelevant_vector"))

    add("merkle-merge-order", "MerkleMergeDirect", "input kp height left current",
        "input kp height current left", merkle_example("merge_two_levels_cached"))
    add("merkle-merge-height", "MerkleMergeDirect", "rest (height + 1) (project reply.1)",
        "rest (height + 2) (project reply.1)", merkle_example("merge_two_levels_cached"))
    add("merkle-merge-remember", "MerkleMergeDirect", "(remember kp height left current state) reply.2",
        "state reply.2", merkle_example("merge_two_levels_cached"))
    add("merkle-merge-cache-reset", "MerkleMergeDirect", "(remember kp height left current state) reply.2",
        "(remember kp height left current state) table", merkle_example("merge_accumulated_cache"))
    add("merkle-merge-rest-lost", "MerkleMergeDirect", "remember kp rest (height + 1)",
        "remember kp [] (height + 1)", merkle_example("merge_two_levels_cached"))
    add("merkle-merge-unmatched-rest-lost", "MerkleMergeDirect",
        "(current, height) :: (left, level) :: rest", "[(current, height)]",
        merkle_example("merge_stops_at_different_height"))

    add("merkle-tree-leaf-order", "MerkleTreeDirect", "(leaf start table).bind",
        "(leaf (start + 1) table).bind", merkle_example("tree_four_leaves_cached"))
    add("merkle-tree-next-index", "MerkleTreeDirect", "remember n (start + 1)",
        "remember n start", merkle_example("tree_four_leaves_cached"))
    add("merkle-tree-final-cache", "MerkleTreeDirect", "PMF.pure ((stack, state), table)",
        "PMF.pure ((stack, state), fun _ => none)", merkle_example("tree_four_leaves_cached"))
    add("merkle-tree-compiler-leaf-index", "MerkleTreeCompiler", "bindProgram (leaf start)",
        "bindProgram (leaf (start + 1))", merkle_example("tree_four_leaves_query_order"))
    add("merkle-tree-compiler-next-index", "MerkleTreeCompiler", "remember n (start + 1)",
        "remember n start", merkle_example("tree_four_leaves_query_order"))

    add("merkle-recovery-child-parity", "MerkleRecoveryDirect",
        "let left := if index % 2 = 0 then current else sibling",
        "let left := if index % 2 = 0 then sibling else current", merkle_example("recovery_even_vector"))
    add("merkle-recovery-default", "MerkleRecoveryDirect", "(auth[height]?).getD 0",
        "(auth[height]?).getD 1", merkle_example("recovery_default_vector"))
    add("merkle-recovery-parent", "MerkleRecoveryDirect", "height (index / 2) left right",
        "height index left right", merkle_example("recovery_odd_vector"))
    add("merkle-recovery-eight-levels", "MerkleRecoveryDirect", "auth 9 0 index leaf table",
        "auth 8 0 index leaf table", merkle_example("recovery_nine_heights"))
    add("merkle-recovery-return-cache", "MerkleRecoveryDirect", "(randomizerOfDigest reply.1) reply.2",
        "(randomizerOfDigest reply.1) table", merkle_example("recovery_one_fresh_populated"))
    add("merkle-recovery-output-zero", "MerkleRecoveryDirect", "(randomizerOfDigest reply.1) reply.2",
        "0 reply.2", merkle_example("recovery_nine_heights"))
    add("merkle-recovery-compiler-index", "MerkleRecoveryCompiler", "steps (height + 1) (index / 2)",
        "steps (height + 1) index", merkle_example("merkle_recovery_query_order"))
    add("merkle-recovery-compiler-height", "MerkleRecoveryCompiler", "steps (height + 1) (index / 2)",
        "steps height (index / 2)", merkle_example("merkle_recovery_query_order"))

    add("merkle-pair-kind-preserving", "MerkleInputs", "c10Address layer tree 2 0 0",
        "c10Address layer tree (1 + 1) 0 0", pair, True)
    add("merkle-keep-side-preserving", "MerkleKeepPure", "leftIndex + 1 = sibling",
        "leftIndex + (0 + 1) = sibling", merkle_example("auth_remember_right_vector"), True)
    add("merkle-tree-index-preserving", "MerkleTreeCompiler", "remember n (start + 1)",
        "remember n (1 + start)", merkle_example("tree_four_leaves_query_order"), True)
    add("merkle-recovery-parent-preserving", "MerkleRecoveryDirect", "height (index / 2) left right",
        "height (index / (1 + 1)) left right", merkle_example("recovery_odd_vector"), True)

    # FORS/forest controls: literal finite witnesses plus the unchanged
    # compiler consumers. Aliases isolate a changed direct procedure from its
    # independently defined compiler, while retaining all dependency proofs.
    def fors_example(name):
        return "set_option maxRecDepth 80000\n" + theorem(src["ForsExamples"], name)

    def fors_alias(module, name, extras=()):
        candidate = name + "Candidate"
        text = merkle_decl(module, name)
        text = re.sub(r"\b" + re.escape(name) + r"\b", candidate, text)
        key = candidate + "Slice"
        src[key] = ("import C10Probability.ForestCached\nnamespace C10Probability\n"
            "noncomputable section\nvariable {K L S : Type*}\n" + text + "\n" +
            "\n".join(merkle_decl(mod, decl) for mod, decl in extras) +
            "end\nend C10Probability\n")
        return key, candidate

    def fors_consumer(module, name, original, candidate):
        return re.sub(r"\b" + re.escape(original) + r"\b", candidate,
                      theorem(src[module], name))

    private = fors_example("fors_private_byte_vector")
    leaf = fors_example("fors_leaf_byte_vector")
    pair = fors_example("fors_pair_byte_vector")
    compression = fors_example("fors_compression_byte_vector")
    add("fors-private-tag-byte", "ForsInputs", "[102, 111, 114, 115]", "[102, 111, 114, 116]", private)
    add("fors-private-ht-width", "ForsInputs", "beBytes 4 ht ++ beBytes 4 tree",
        "beBytes 8 ht ++ beBytes 4 tree", private)
    add("fors-private-coordinate-order", "ForsInputs", "beBytes 4 tree ++ beBytes 4 leaf",
        "beBytes 4 leaf ++ beBytes 4 tree", private)
    add("fors-leaf-kind", "ForsInputs", "c10Address 0 ht 3 tree 0 0 leaf",
        "c10Address 0 ht 2 tree 0 0 leaf", leaf)
    add("fors-leaf-index", "ForsInputs", "c10Address 0 ht 3 tree 0 0 leaf",
        "c10Address 0 ht 3 tree 0 0 tree", leaf)
    add("fors-pair-height", "ForsInputs", "(height + 1) parent", "height parent", pair)
    add("fors-pair-child-order", "ForsInputs", "nodeBlock left ++ nodeBlock right",
        "nodeBlock right ++ nodeBlock left", pair)
    add("fors-tree-pair-parent", "ForsInputs", "(leaf / 2 ^ (height + 1))",
        "(leaf / 2 ^ height)", fors_example("fors_tree_pair_parent_vector"))
    add("fors-compression-kind", "ForsInputs", "c10Address 0 ht 4 0 0 0 0",
        "c10Address 0 ht 3 0 0 0 0", compression)
    add("fors-compression-root-order", "ForsInputs", "roots.flatMap nodeBlock",
        "roots.reverse.flatMap nodeBlock", compression)
    add("fors-index-field-stride", "ForsInputs", "(11 * tree) % 2048", "(12 * tree) % 2048",
        fors_example("forest_digest_field_vector"))
    add("fors-index-field-width", "ForsInputs", "(11 * tree) % 2048", "(11 * tree) % 4096",
        fors_example("forest_digest_upper_boundary"))
    add("fors-private-tag-equivalent", "ForsInputs", "[102, 111, 114, 115]",
        "[102, 111, 114, 114 + 1]", private, True)

    merkle_slice("ForsRememberPure", ["ForsInputs"], [("ForsTree", "forsRemember")])
    add("fors-auth-left-value", "ForsRememberPure", "then auth.set height left else auth",
        "then auth.set height right else auth", fors_example("fors_remember_left_vector"))
    add("fors-auth-right-value", "ForsRememberPure", "then auth.set height right else auth",
        "then auth.set height left else auth", fors_example("fors_remember_right_vector"))
    add("fors-auth-high-slot", "ForsRememberPure", "auth.set height right",
        "auth.set (height + 1) right", fors_example("fors_remember_high_vector"))
    add("fors-auth-irrelevant-write", "ForsRememberPure", "sibling * 2 ^ height = rightStart",
        "True", fors_example("fors_remember_irrelevant_vector"))
    add("fors-auth-overwrite-suppressed", "ForsRememberPure", "then auth.set height left else auth",
        "then (if (auth[height]?).getD 0 = 0 then auth.set height left else auth) else auth",
        fors_example("fors_remember_overwrite_vector"))
    add("fors-auth-coordinate-shift", "ForsRememberPure", "(leaf / 2 ^ (height + 1)) * 2 ^ (height + 1)",
        "leaf", fors_example("fors_remember_left_vector"))

    key, alias = fors_alias("ForsLeaf", "forsLeafProgram")
    trace = fors_example("fors_leaf_query_order").replace("forsLeafProgram", alias)
    add("fors-leaf-private-route", key, ".inr (forsPrivateTail", ".inl (forsPrivateTail", trace)
    add("fors-leaf-secret-projection", key, "(randomizerOfDigest secret)", "0", trace)
    key, alias = fors_alias("ForsLeaf", "forsLeaf")
    check = fors_consumer("ForsLeaf", "fors_leaf_eval", "forsLeaf", alias)
    add("fors-leaf-history-reset", key, "memoQuery digestDraw secret.2", "memoQuery digestDraw table", check)
    add("fors-leaf-return-table", key, "reply.1, reply.2)", "reply.1, table)", check)

    key, alias = fors_alias("ForsTree", "forsSign")
    check = fors_consumer("ForsTree", "fors_sign_eval", "forsSign", alias)
    add("fors-sign-secret-history", key, "forsTree encode secret.2", "forsTree encode table", check)
    add("fors-sign-root-in-secret-slot", key, "randomizerOfDigest secret.1, out.1.2",
        "out.1.1, out.1.2", check)

    merkle_slice("ForsRecoveryPure", ["ForsInputs"], [("ForsRecover", "forsRecoveryInput")])
    add("fors-recover-left-parity", "ForsRecoveryPure", "then current else sibling",
        "then sibling else current", fors_example("fors_recovery_even_vector"))
    add("fors-recover-default", "ForsRecoveryPure", "(auth[height]?).getD 0",
        "(auth[height]?).getD 1", fors_example("fors_recovery_default_vector"))
    add("fors-recover-parent", "ForsRecoveryPure", "(index / 2) left right",
        "index left right", fors_example("fors_recovery_odd_vector"))
    key, alias = fors_alias("ForsRecover", "forsRecoveryProgram")
    # Include only the wrapper as a renamed definition; dependency references
    # point at the mutated recursive compiler, not the original imported one.
    wrapper = merkle_decl("ForsRecover", "forsRecoverProgram").replace(
        "forsRecoveryProgram", alias).replace("forsRecoverProgram", "forsRecoverCandidate")
    src[key] = src[key].replace("end\nend C10Probability\n", wrapper + "end\nend C10Probability\n")
    trace = fors_example("fors_recovery_query_order").replace("forsRecoveryProgram", alias).replace(
        "forsRecoverProgram", "forsRecoverCandidate")
    add("fors-recover-index-step", key, "steps (height + 1) (index / 2)",
        "steps (height + 1) index", trace)
    add("fors-recover-height-step", key, "steps (height + 1) (index / 2)",
        "steps height (index / 2)", trace)
    key, alias = fors_alias("ForsRecover", "forsRecoverProgram")
    trace = fors_example("fors_recovery_query_order").replace("forsRecoverProgram", alias)
    add("fors-recover-eleventh-call-lost", key,
        "forsRecoveryProgram encode seed ht tree auth 11 0 target (randomizerOfDigest reply)",
        "reserveProgram 1 (forsRecoveryProgram encode seed ht tree auth 10 0 target (randomizerOfDigest reply))",
        trace.replace("forsRecoveryProgram, traceProgram", "forsRecoveryProgram, reserveProgram, traceProgram"))
    key, alias = fors_alias("ForsRecover", "forsRecoveryLoop")
    add("fors-recover-fresh-cache-lost", key, "(current, table)", "(current, fun _ => none)",
        fors_example("fors_recovery_one_fresh_populated").replace("forsRecoveryLoop", alias))

    merkle_slice("ShuffleDeriveInputs", ["ForsInputs"],
        [("ShuffleDerive", n) for n in ["shuffleTag", "shuffleDeriveInput"]])
    add("forest-shuffle-domain-tag", "ShuffleDeriveInputs", "108,101,45,118,49]",
        "108,101,45,118,50]", fors_example("forest_shuffle_derive_vector"))
    add("forest-shuffle-label-order", "ShuffleDeriveInputs", "shuffleTag ++ seed ++ label",
        "shuffleTag ++ label ++ seed", fors_example("forest_shuffle_derive_vector"))
    key, alias = fors_alias("ShuffleDerive", "shuffleDeriveProgram")
    wrapper = merkle_decl("ForestShuffle", "forestShuffleProgram").replace(
        "shuffleDeriveProgram", alias).replace("forestShuffleProgram", "forestShuffleCandidate")
    src[key] = src[key].replace("end\nend C10Probability\n", wrapper + "end\nend C10Probability\n")
    trace = fors_example("forest_shuffle_full_query_order").replace("shuffleDeriveProgram", alias).replace(
        "forestShuffleProgram", "forestShuffleCandidate")
    add("forest-shuffle-truncated-subseed", key, "secretBytes reply",
        "nodeBlock (randomizerOfDigest reply)", trace)
    add("forest-shuffle-zero-queries", key, "if seed = List.replicate 32 0 then",
        "if seed = [] then", fors_example("forest_shuffle_zero_query_trace").replace(
            "shuffleDeriveProgram", alias).replace("forestShuffleProgram", "forestShuffleCandidate"))
    key, alias = fors_alias("ForestShuffle", "forestPermutationProgram")
    trace = fors_example("forest_permutation_query_order").replace("forestPermutationProgram", alias)
    add("forest-shuffle-fourth-block-lost", key, "(shuffleBlocksProgram encode seed 0 4)",
        "(reserveProgram 1 (shuffleBlocksProgram encode seed 0 3))",
        trace.replace("shuffleBlocksProgram,", "shuffleBlocksProgram, reserveProgram,"))
    add("forest-shuffle-four-blocks-equivalent", key, "(shuffleBlocksProgram encode seed 0 4)",
        "(shuffleBlocksProgram encode seed 0 (2 + 2))", trace, True)
    merkle_slice("ForestShufflePure", ["WotsShuffle"],
        [("ForestShuffle", n) for n in ["forestTreeIndices", "forestShuffleSwap", "forestShuffleLoop"]])
    trace = fors_example("forest_shuffle_patterned_order")
    add("forest-shuffle-second-write", "ForestShufflePure", ".set j ((order[i]?).getD 0)",
        ".set i ((order[i]?).getD 0)", trace)
    add("forest-shuffle-stride", "ForestShufflePure", "stream i (pos + 2)", "stream i (pos + 1)", trace)
    add("forest-shuffle-visit", "ForestShufflePure", "order (i + 1) (shuffleChoice stream pos (i + 1))",
        "order i (shuffleChoice stream pos i)", trace)
    add("forest-shuffle-stride-equivalent", "ForestShufflePure", "stream i (pos + 2)",
        "stream i (pos + (1 + 1))", trace, True)

    key, alias = fors_alias("ForestOne", "forestOne")
    check = fors_consumer("ForestOne", "forest_one_eval", "forestOne", alias)
    add("forest-one-recovery-history", key, ") sig.2 seed ht tree target", ") table seed ht tree target", check)
    add("forest-one-recovery-target", key, ") sig.2 seed ht tree target", ") sig.2 seed ht tree 0", check)
    add("forest-one-secret-as-root", key, "sig.1.2, root.1", "sig.1.2, sig.1.1", check)
    key, alias = fors_alias("ForestFill", "forestWrite")
    check = fors_example("forest_positional_write_vector").replace("forestWrite", alias)
    add("forest-fill-secret-position", key, "secrets.set tree", "secrets.set 0", check)
    add("forest-fill-auth-position", key, "auths.set tree", "auths.set 0", check)
    add("forest-fill-root-position", key, "roots.set tree", "roots.set 0", check)
    key, alias = fors_alias("ForestFill", "forestFillLoop")
    check = fors_consumer("ForestFill", "forest_fill_eval", "forestFillLoop", alias)
    add("forest-fill-index-field", key, "(forestIndex digest tree.val)", "(forestIndex digest 0)", check)
    add("forest-fill-cache-reset", key, "(forestWrite state tree.val out.1) out.2",
        "(forestWrite state tree.val out.1) table", check)
    add("forest-fill-state-discarded", key, "(forestWrite state tree.val out.1) out.2", "state out.2", check)

    key, alias = fors_alias("ForestSign", "forestLastProgram")
    trace = fors_example("forest_last_query_order").replace("forestLastProgram", alias)
    add("forest-last-leaf-index", key, "ht 12 0 last", "ht 12 1 last", trace)
    add("forest-last-unhashed-compression", key, "state.roots.set 12 (randomizerOfDigest leaf)",
        "state.roots.set 12 last", trace)
    add("forest-last-compression-order", key, "(state.roots.set 12 (randomizerOfDigest leaf))",
        "(state.roots.set 12 (randomizerOfDigest leaf)).reverse", trace)
    key, alias = fors_alias("ForestSign", "forestLast")
    check = fors_consumer("ForestSign", "forest_last_eval", "forestLast", alias)
    add("forest-last-hashed-transmitted-secret", key, "state.secrets.set 12 last",
        "state.secrets.set 12 (randomizerOfDigest leaf.1)", check)
    add("forest-last-leaf-as-pk", key, "state.auths, randomizerOfDigest reply.1",
        "state.auths, randomizerOfDigest leaf.1", check)
    add("forest-last-compression-history", key, "memoQuery digestDraw leaf.2",
        "memoQuery digestDraw table", check)
    add("forest-last-final-table", key, "reply.2)))", "table)))", check)
    key, alias = fors_alias("ForestSign", "forestFinish")
    check = fors_consumer("ForestSign", "forest_finish_eval", "forestFinish", alias)
    add("forest-finish-thirteenth-tree", key, "forsRoot encode table seed ht 12",
        "forsRoot encode table seed ht 11", check)
    add("forest-finish-root-history", key, "forestLast encode last.2", "forestLast encode table", check)
    key, alias = fors_alias("ForestSign", "forestSign")
    check = fors_consumer("ForestSign", "forest_sign_eval", "forestSign", alias)
    add("forest-sign-order-discarded", key, "digest order.1.val emptyForestState",
        "digest forestTreeIndices emptyForestState", check)
    add("forest-sign-shuffle-history", key, "emptyForestState order.2", "emptyForestState table", check)
    add("forest-sign-filled-history", key, "forestFinish encode filled.2", "forestFinish encode table", check)
    add("forest-sign-filled-state", key, "seed ht filled.1", "seed ht emptyForestState", check)

    key, alias = fors_alias("ForestRecover", "forestRecoveryLoop")
    check = fors_consumer("ForestRecover", "forest_recovery_program_eval", "forestRecoveryLoop", alias)
    add("forest-recover-root-order", key, "(roots ++ [out.1]) out.2", "(out.1 :: roots) out.2", check)
    add("forest-recover-tree-field", key, "(forestIndex digest tree.val)", "(forestIndex digest 0)", check)
    add("forest-recover-cache-reset", key, "(roots ++ [out.1]) out.2", "(roots ++ [out.1]) table", check)
    key, alias = fors_alias("ForestRecover", "forestRecover")
    check = fors_consumer("ForestRecover", "forest_recover_eval", "forestRecover", alias)
    add("forest-recover-last-secret-position", key, "(secrets[12]?).getD 0", "(secrets[11]?).getD 0", check)
    add("forest-recover-unhashed-last", key, "roots.1 ++ [randomizerOfDigest last.1]",
        "roots.1 ++ [((secrets[12]?).getD 0)]", check)
    add("forest-recover-final-table", key, "reply.1, reply.2)", "reply.1, table)", check)
    add("forest-recover-root-list-equivalent", key, "roots.1 ++ [randomizerOfDigest last.1]",
        "roots.1 ++ (randomizerOfDigest last.1 :: [])", check, True)


    # Complete C10 clients: source-derived aliases retain the independent
    # compiler and finite consumers. Definitions and baselines must compile;
    # diagnostics from non-reduction or resource failure never count.
    def client_alias(module, name):
        candidate = name + "BMCandidate"
        text = re.sub(r"\b" + re.escape(name) + r"\b", candidate, merkle_decl(module, name))
        key = candidate + "Slice"
        src[key] = ("import C10Probability.C10Examples\nnamespace C10Probability\n"
            "noncomputable section\nvariable {K L : Type*}\n" + text +
            "\nend\nend C10Probability\n")
        return key, candidate

    def client_check(module, name, original, candidate):
        return "set_option maxRecDepth 4096\n" + re.sub(
            r"\b" + re.escape(original) + r"\b", candidate, theorem(src[module], name))

    def client_cases(module, definition, consumer_module, consumer, rows):
        key, alias = client_alias(module, definition)
        check = client_check(consumer_module, consumer, definition, alias)
        for row in rows:
            add(row[0], key, row[1], row[2], check, row[3] if len(row) == 4 else False)

    client_cases("LayerInputs", "layerShuffleLabel", "LayerExamples", "layer_zero_label_vector", [
        ("layer-label-zero-byte", "45,48,0]", "45,49,0]"),
        ("layer-label-zero-terminator", "45,48,0]", "45,48]"),
        ("layer-label-branch", "layer = 0", "layer = 1"),
        ("layer-label-zero-equivalent", "45,48,0]", "45,47 + 1,0]", True)])
    client_cases("LayerInputs", "layerShuffleLabel", "LayerExamples", "layer_one_label_vector", [
        ("layer-label-one-byte", "45,49,0]", "45,48,0]"),
        ("layer-label-one-terminator", "45,49,0]", "45,49]"),
        ("layer-label-one-equivalent", "45,49,0]", "45,48 + 1,0]", True)])
    client_cases("LayerInputs", "layerShuffleLabel", "LayerExamples", "layer_other_label_vector", [
        ("layer-label-nonzero-domain", "layer = 0", "layer != 1")])
    client_cases("LayerInputs", "hypertreeIndex", "LayerExamples", "hypertree_first_bit", [
        ("hypertree-index-start", "2 ^ 143", "2 ^ 144")])
    client_cases("LayerInputs", "hypertreeIndex", "LayerExamples", "hypertree_high_bit_boundary", [
        ("hypertree-index-width", "% 2 ^ 18", "% 2 ^ 19")])
    client_cases("LayerInputs", "hypertreeLeaf", "LayerExamples", "hypertree_last_coordinate_vector", [
        ("hypertree-leaf-width", "index % 512", "index % 256")])
    client_cases("LayerInputs", "hypertreeParent", "LayerExamples", "hypertree_last_coordinate_vector", [
        ("hypertree-parent-shift", "index / 512", "index / 256")])
    client_cases("LayerInputs", "wotsRecoverCountInput", "LayerExamples", "layer_count_full_block_vector", [
        ("layer-count-width", "beBytes 32 count", "beBytes 4 count"),
        ("layer-count-position", "++ beBytes 32 count", "++ (beBytes 32 count).reverse"),
        ("layer-count-bytes-equivalent", "beBytes 32 count", "beBytes (16 + 16) count", True)])
    client_cases("LayerInputs", "wotsRecoverCountInput", "LayerExamples", "layer_natural_count_not_u32_wrapped", [
        ("layer-count-natural-wrapped", "beBytes 32 count", "beBytes 32 (count % 2 ^ 32)")])
    client_cases("LayerInputs", "nodeValueBytes", "LayerExamples", "layer_message_byte_vector", [
        ("layer-message-byte-order", "List.ofFn (randomizerBytesEquiv.symm value)",
         "(List.ofFn (randomizerBytesEquiv.symm value)).reverse")])

    client_cases("RecoveryRelabel", "wotsRecoverChainsUnder", "RecoveryRelabel", "wots_recover_chains_under_eval", [
        ("relabel-chain-start", "(fun i => (word i).val)", "(fun _ => 0)"),
        ("relabel-chain-remaining", "(fun i => 7 - (word i).val)", "(fun i => 6 - (word i).val)"),
        ("relabel-chain-position", "kp i.val step node", "kp 0 step node"),
        ("relabel-chain-cache-reset", "sigma wotsIndices table", "sigma wotsIndices (fun _ => none)")])
    client_cases("RecoveryRelabel", "wotsCompressUnder", "RecoveryRelabel", "wots_compress_under_eval", [
        ("relabel-compression-order", "kp values", "kp values.reverse"),
        ("relabel-compression-cache", "out.1, out.2)", "out.1, table)")])
    client_cases("WotsRecoveryUnder", "wotsRecoveryUnder", "WotsRecoveryUnder", "wots_recovery_under_eval", [
        ("layer-wots-count-cache", "encode counted.2 seed", "encode table seed"),
        ("layer-wots-chain-cache", "encode chains.2 seed", "encode table seed"),
        ("layer-wots-reject-cache", "PMF.pure (0, counted.2)", "PMF.pure (0, table)"),
        ("layer-wots-reject-node", "PMF.pure (0, counted.2)", "PMF.pure (1, counted.2)"),
        ("layer-wots-count-coordinate", "seed layer tree kp message count", "seed layer tree 0 message count")])
    client_cases("LayerRecover", "layerRecover", "LayerRecover", "layer_recover_eval", [
        ("layer-recover-count", "sig.sigma sig.count", "sig.sigma 0"),
        ("layer-recover-auth", "pk.1 leaf sig.auth", "pk.1 leaf []"),
        ("layer-recover-history", "encode pk.2 seed", "encode table seed"),
        ("layer-recover-leaf", "pk.1 leaf sig.auth", "pk.1 0 sig.auth"),
        ("layer-recover-wots-node", "pk.1 leaf sig.auth", "message leaf sig.auth")])
    client_cases("LayerSign", "layerSignAfter", "LayerSign", "layer_sign_after_eval", [
        ("layer-sign-exhaustion-cache", "PMF.pure (none, table)", "PMF.pure (none, fun _ => none)"),
        ("layer-sign-return-counter", "⟨sigma, count, auth⟩", "⟨sigma, count + 1, auth⟩"),
        ("layer-sign-return-auth", "⟨sigma, count, auth⟩", "⟨sigma, count, []⟩"),
        ("layer-sign-reconstructed-root", "(some (sig, root.1), root.2)", "(some (sig, message), root.2)"),
        ("layer-sign-recovery-history", "(some (sig, root.1), root.2)", "(some (sig, root.1), table)")])
    client_cases("LayerSign", "layerSign", "LayerSign", "layer_sign_eval", [
        ("layer-sign-built-history", "(layerShuffleLabel layer) built.2", "(layerShuffleLabel layer) table"),
        ("layer-sign-subseed-history", "wotsSign encode subseed.2", "wotsSign encode table"),
        ("layer-sign-subseed-value", "message) subseed.1 n hb", "message) shuffle n hb"),
        ("layer-sign-signed-history", "layerSignAfter encode signed.2", "layerSignAfter encode table"),
        ("layer-sign-built-auth", "message built.1.1 signed.1", "message [] signed.1"),
        ("layer-sign-wrong-label", "(layerShuffleLabel layer)", "(layerShuffleLabel 0)")])
    client_cases("HypertreeSign", "hypertreeSign", "HypertreeSign", "hypertree_sign_eval", [
        ("hypertree-sign-unshifted-tree", "seed layer (hypertreeParent index)", "seed layer index"),
        ("hypertree-sign-leaf", "(hypertreeLeaf index) current", "0 current"),
        ("hypertree-sign-layer-repeated", "(layer + 1)", "layer"),
        ("hypertree-sign-root-discarded", "index) root (signatures", "index) current (signatures"),
        ("hypertree-sign-signature-prepend", "(signatures ++ [sig])", "(sig :: signatures)"),
        ("hypertree-sign-history-reset", "[sig]) signed.2", "[sig]) table"),
        ("hypertree-sign-failure-cache", "PMF.pure (none, signed.2)", "PMF.pure (none, table)"),
        ("hypertree-sign-next-layer-equivalent", "(layer + 1)", "(layer + (0 + 1))", True)])
    client_cases("HypertreeRecover", "hypertreeRecover", "HypertreeRecover", "hypertree_recover_eval", [
        ("hypertree-recover-leaf", "(hypertreeLeaf index)", "0"),
        ("hypertree-recover-signature-index", "signatures[layer]?", "signatures[0]?"),
        ("hypertree-recover-layer-repeated", "(layer + 1)", "layer"),
        ("hypertree-recover-root-discarded", "index) root.1 root.2", "index) current root.2"),
        ("hypertree-recover-history-reset", "index) root.1 root.2", "index) root.1 table")])
    client_cases("C10Finish", "c10FinishOutput", "C10Examples", "c10_finish_output_fields", [
        ("c10-output-r", "⟨randomizer, forest.secrets", "⟨0, forest.secrets"),
        ("c10-output-secrets", "forest.secrets, forest.auths", "[], forest.auths"),
        ("c10-output-auths", "forest.auths, result.1", "[], result.1"),
        ("c10-output-layer-order", "forest.auths, result.1", "forest.auths, result.1.reverse")])
    client_cases("C10Finish", "c10Finish", "C10Finish", "c10_finish_eval", [
        ("c10-finish-single-layer", "n hb 2 0", "n hb 1 0"),
        ("c10-finish-initial-layer", "n hb 2 0", "n hb 2 1"),
        ("c10-finish-forest-root", "forest.1.pk []", "0 []"),
        ("c10-finish-forest-history", "[] forest.2", "[] table"),
        ("c10-finish-final-history", "signed.1, signed.2", "signed.1, table"),
        ("c10-finish-two-equivalent", "n hb 2 0", "n hb (1 + 1) 0", True)])
    client_cases("RandomizerUnder", "randomizerUnder", "RandomizerUnder", "randomizer_under_eval", [
        ("c10-r-private-route", "encode (.inr key)", "encode (.inl key)"),
        ("c10-r-message-order", "hmsgRandomizerInput seed root message r", "hmsgRandomizerInput root seed message r"),
        ("c10-r-derivation-message", "rTailStem random message", "rTailStem message random"),
        ("c10-r-accepted-counter", "table 0", "table 1"),
        ("c10-r-cache-reset", "table 0", "(fun _ => none) 0")])
    client_cases("C10Sign", "c10SignAfter", "C10Sign", "c10_sign_after_eval", [
        ("c10-sign-r-exhaustion-history", "PMF.pure (none, table)", "PMF.pure (none, fun _ => none)"),
        ("c10-sign-found-r", "table seed randomizer digest", "table seed 0 digest"),
        ("c10-sign-found-digest", "table seed randomizer digest", "table seed randomizer 0")])
    client_cases("C10Sign", "c10Sign", "C10Sign", "c10_sign_eval", [
        ("c10-sign-r-history", "encode found.2 seed", "encode table seed"),
        ("c10-sign-r-message", "table random message seed root", "table message random seed root"),
        ("c10-sign-found-discarded", "n hn found.1", "n hn none")])
    client_cases("C10Verify", "c10VerifyAfter", "C10Verify", "c10_verify_after_eval", [
        ("c10-verify-forced-zero-negated", "if forsAccept (forsOfDigest digest) then", "if !forsAccept (forsOfDigest digest) then"),
        ("c10-verify-forced-zero-skipped", "if forsAccept (forsOfDigest digest) then", "if true then"),
        ("c10-verify-forest-secret-order", "digest sig.secrets sig.auths", "digest sig.secrets.reverse sig.auths"),
        ("c10-verify-single-layer", "sig.layers 2 0", "sig.layers 1 0"),
        ("c10-verify-initial-layer", "sig.layers 2 0", "sig.layers 2 1"),
        ("c10-verify-forest-root", "digest) pk.1 pk.2", "digest) 0 pk.2"),
        ("c10-verify-forest-history", "digest) pk.1 pk.2", "digest) pk.1 table"),
        ("c10-verify-final-history", "root), current.2", "root), table"),
        ("c10-verify-root-prefix-only", "decide (nodeBlock current.1 = root)", "decide (nodeValueBytes current.1 = root.take 16)"),
        ("c10-verify-reject-history", "PMF.pure (false, table)", "PMF.pure (false, fun _ => none)"),
        ("c10-verify-two-equivalent", "sig.layers 2 0", "sig.layers (1 + 1) 0", True)])
    client_cases("C10Verify", "c10Verify", "C10Verify", "c10_verify_eval", [
        ("c10-verify-signature-r", "message sig.randomizer", "message 0"),
        ("c10-verify-hmsg-order", "hmsgRandomizerInput seed root message", "hmsgRandomizerInput root seed message"),
        ("c10-verify-hmsg-history", "encode digest.2 seed", "encode table seed"),
        ("c10-verify-hmsg-reply", "root sig digest.1", "root sig 0")])
    client_cases("C10Keygen", "c10Keygen", "C10Keygen", "c10_keygen_eval", [
        ("c10-keygen-layer", "table seed 1 0", "table seed 0 0"),
        ("c10-keygen-tree", "table seed 1 0", "table seed 1 1"),
        ("c10-keygen-public-seed", "randomizerOfDigest publicSeed", "(⟨publicSeed.val % 2 ^ 128, Nat.mod_lt _ (by decide)⟩ : Randomizer)"),
        ("c10-keygen-root-pad", "nodeBlock root.1", "nodeValueBytes root.1"),
        ("c10-keygen-returned-cache", "root.1), root.2", "root.1), table")])


    # Adaptive structured session: independently retained compiler/PMF and
    # finite consumers check state transitions, cache history and final guards.
    def session_alias(module, name):
        candidate = name + "BNCandidate"
        match = re.search(r"^(?:def|abbrev) " + re.escape(name) +
                          r"\b.*?(?=^(?:theorem|def|abbrev|structure|inductive|end|attribute)\b)",
                          src[module], flags=re.M | re.S)
        if not match:
            raise ValueError("missing session definition " + name)
        text = re.sub(r"\b" + re.escape(name) + r"\b", candidate, match.group(0))
        key = candidate + "Slice"
        src[key] = ("import C10Probability.SessionExamples\nnamespace C10Probability\n"
            "noncomputable section\nvariable {K L R : Type*}\n" + text +
            "\nend\nend C10Probability\n")
        return key, candidate

    def session_cases(module, definition, consumer_module, consumer, rows):
        key, alias = session_alias(module, definition)
        check = re.sub(r"\b" + re.escape(definition) + r"\b", alias,
                      theorem(src[consumer_module], consumer))
        for row in rows:
            add(row[0], key, row[1], row[2], check, row[3] if len(row) == 4 else False)

    session_cases("SessionTypes", "sessionAdmits", "SessionExamples", "session_admission_vectors", [
        ("session-admit-failed", "!ledger.failed", "true"),
        ("session-admit-message", "req.message.length = 32", "req.message.length = 31"),
        ("session-admit-random-empty", "req.random.length = 0", "req.random.length = 1"),
        ("session-admit-random-sixteen", "req.random.length = 16", "req.random.length = 15"),
        ("session-admit-shuffle", "req.shuffle.length = 32", "req.shuffle.length = 33"),
        ("session-admit-equivalent", "req.message.length = 32", "req.message.length = 16 + 16", True)])
    session_cases("SessionTypes", "sessionAfterSign", "SessionTypes", "session_none_absorbs", [
        ("session-none-failure", "⟨ledger.signedMessages, true⟩", "⟨ledger.signedMessages, false⟩"),
        ("session-none-recorded", "⟨ledger.signedMessages, true⟩", "⟨ledger.signedMessages ++ [message], true⟩"),
        ("session-none-erased", "⟨ledger.signedMessages, true⟩", "⟨[], true⟩")])
    session_cases("SessionTypes", "sessionAfterSign", "SessionTypes", "session_some_records", [
        ("session-some-missing", "ledger.signedMessages ++ [message]", "ledger.signedMessages"),
        ("session-some-prepended", "ledger.signedMessages ++ [message]", "message :: ledger.signedMessages"),
        ("session-some-clears-failed", "ledger.failed⟩", "false⟩")])
    session_cases("SessionProgram", "c10Session", "SessionProgram", "c10_session_eval", [
        ("session-done-ledger-reset", "PMF.pure (⟨value, ledger, qr, qs⟩, table)",
         "PMF.pure (⟨value, emptySessionLedger, qr, qs⟩, table)"),
        ("session-done-raw-cap", "PMF.pure (⟨value, ledger, qr, qs⟩, table)",
         "PMF.pure (⟨value, ledger, qr + 1, qs⟩, table)"),
        ("session-hash-capped-default", "(next 0) 0 qs ledger table", "(next 1) 0 qs ledger table"),
        ("session-hash-private-route", "(encode (.inl key))", "(encode (.inr key))"),
        ("session-hash-reply-discarded", "(next reply.1) qr qs ledger reply.2", "(next 0) qr qs ledger reply.2"),
        ("session-hash-cap-not-spent", "(next reply.1) qr qs ledger reply.2", "(next reply.1) (qr + 1) qs ledger reply.2"),
        ("session-hash-cache-discarded", "(next reply.1) qr qs ledger reply.2", "(next reply.1) qr qs ledger table"),
        ("session-zero-sign-cap-increased", "(next none) qr 0 ledger table", "(next none) qr 1 ledger table"),
        ("session-admission-skipped", "if sessionAdmits ledger req then", "if true then"),
        ("session-sign-random-message-swapped", "table req.random req.message cfg.seed", "table req.message req.random cfg.seed"),
        ("session-sign-seed-root-swapped", "req.message cfg.seed cfg.root req.shuffle", "req.message cfg.root cfg.seed req.shuffle"),
        ("session-sign-cap-not-spent", "(next reply.1) qr qs\n", "(next reply.1) qr (qs + 1)\n"),
        ("session-sign-response-discarded", "(next reply.1) qr qs\n", "(next none) qr qs\n"),
        ("session-sign-cache-discarded", "(sessionAfterSign ledger req.message reply.1) reply.2", "(sessionAfterSign ledger req.message reply.1) table"),
        ("session-sign-ledger-skipped", "(sessionAfterSign ledger req.message reply.1) reply.2", "ledger reply.2"),
        ("session-refused-sign-spends-cap", "(next none) qr (qs + 1) ledger table", "(next none) qr qs ledger table"),
        ("session-refused-sign-clears-cache", "(next none) qr (qs + 1) ledger table", "(next none) qr (qs + 1) ledger (fun _ => none)"),
        ("session-hash-remaining-equivalent", "if sessionAdmits ledger req then", "if (fun value : Bool => value) (sessionAdmits ledger req) then", True)])
    session_cases("SessionDriver", "sessionSignatureWidth", "SessionDriver", "session_signature_width_iff", [
        ("session-width-secrets", "sig.secrets.length = 13", "sig.secrets.length = 12"),
        ("session-width-auth-rows", "sig.auths.length = 12", "sig.auths.length = 11"),
        ("session-width-auth-height", "auth.length = 11", "auth.length = 10"),
        ("session-width-layer-count", "sig.layers.length = 2", "sig.layers.length = 1"),
        ("session-width-u32", "layer.count < 2 ^ 32", "layer.count < 2 ^ 33"),
        ("session-width-layer-auth", "layer.auth.length = 9", "layer.auth.length = 8"),
        ("session-width-layer-equivalent", "sig.layers.length = 2", "sig.layers.length = 1 + 1", True)])
    session_cases("SessionDriver", "sessionFinalAdmits", "SessionDriver", "session_final_admits_iff", [
        ("session-final-ignore-failure", "!out.ledger.failed", "true"),
        ("session-final-message-width", "out.value.1.length = 32", "out.value.1.length = 31"),
        ("session-final-shape-skipped", "sessionSignatureWidth out.value.2", "true"),
        ("session-final-replay-required", "out.value.1 ∉ out.ledger.signedMessages", "out.value.1 ∈ out.ledger.signedMessages"),
        ("session-final-ledger-ignored", "out.value.1 ∉ out.ledger.signedMessages", "out.value.1 ∉ ([] : List ByteKey)")])
    session_cases("SessionDriver", "c10Final", "SessionDriver", "c10_final_eval", [
        ("session-final-guard-skipped", "if sessionFinalAdmits out then", "if true then"),
        ("session-final-private-verify", "encode ∘ Sum.inl", "encode ∘ Sum.inr"),
        ("session-final-root-swapped", "cfg.seed cfg.root out.value.1", "cfg.root cfg.seed out.value.1"),
        ("session-final-cache-reset", "table cfg.seed", "(fun _ => none) cfg.seed"),
        ("session-final-refusal-true", "PMF.pure (false, table)", "PMF.pure (true, table)"),
        ("session-final-refusal-cache", "PMF.pure (false, table)", "PMF.pure (false, fun _ => none)")])
    session_cases("SessionDriver", "c10Driver", "SessionDriver", "c10_driver_eval", [
        ("session-driver-swapped-caps", "client qr qs emptySessionLedger", "client qs qr emptySessionLedger"),
        ("session-driver-cache-discarded", "out.1 out.2", "out.1 table")])
    session_cases("SessionGame", "sessionConfigAt", "SessionGame", "session_config_at_fields", [
        ("session-game-public-root", "root := key.2", "root := key.1")])
    session_cases("SessionGame", "c10Game", "SessionGame", "c10_game_eval", [
        ("session-game-keygen-cache-reset", "encode table publicSeed", "encode (fun _ => none) publicSeed"),
        ("session-game-keygen-seed-zero", "encode table publicSeed", "encode table 0"),
        ("session-game-client-input-swapped", "adversary key.1.1 key.1.2", "adversary key.1.2 key.1.1"),
        ("session-game-driver-cache-reset", "qr qs key.2", "qr qs table"),
        ("session-game-no-raw-cap", "qr qs key.2", "0 qs key.2"),
        ("session-game-sign-cap-equivalent", "qr qs key.2", "qr (qs + 0) key.2", True)])
    for definition, target, old, new in [
        ("sessionGameRaw", "121482646", "177512", "177511"),
        ("sessionGamePublic", "91248368", "155496", "155495"),
        ("sessionGameSelected", "31482637", "177509", "177508")]:
        key, alias = session_alias("SessionCharges", definition)
        check = ("theorem checked : " + alias +
            " (⟨[],[],10000000,10000000,by decide,by decide⟩) 2 3 = " + target +
            " := by decide +kernel\n")
        add("session-game-cost-" + definition, key, old, new, check)


    # Passive observed histories and final-cache witnesses. Each mutated
    # definition compiles separately; the unchanged consumer must reject it.
    def observed_alias(module, name):
        alias = name + "BOCandidate"
        text = re.sub(r"\b" + re.escape(name) + r"\b", alias, merkle_decl(module, name))
        key = alias + "Slice"
        src[key] = ("import C10Probability.ObservedExamples\nnamespace C10Probability\n"
            "noncomputable section\nvariable {K L R T α : Type*}\n" + text +
            "\nend\nend C10Probability\n")
        return key, alias

    def observed_cases(module, definition, consumer_module, consumer, rows):
        key, alias = observed_alias(module, definition)
        check = re.sub(r"\b" + re.escape(definition) + r"\b", alias,
                      theorem(src[consumer_module], consumer))
        for row in rows:
            add(row[0], key, row[1], row[2], check, row[3] if len(row) == 4 else False)

    observed_cases("QueryReplay", "replayProgram", "ObservedExamples", "replay_repeat_example", [
        ("observed-replay-missing-reply", "(table key).bind", "(none : Option α).bind"),
        ("observed-replay-done-drop", "| _, .done value => some value", "| _, .done _ => none"),
        ("observed-replay-equivalent", "(table key).bind", "((fun x => x) (table key)).bind", True)])
    observed_cases("ObservedSession", "observeHash", "ObservedSession", "observe_hash_session", [
        ("observed-hash-corrupt-cap", "{ out with queries := key :: out.queries }",
         "{ out with session := { out.session with rawRemaining := out.session.rawRemaining + 1 }, queries := key :: out.queries }")])
    key, alias = observed_alias("ObservedSession", "observeHash")
    check = ("theorem checked (key : ByteKey) (out : C10ObservedSession R) :\n"
        "    (" + alias + " key out).queries = key :: out.queries := rfl\n")
    for name, old, new, expected in [
        ("observed-hash-log-drop", "key :: out.queries", "out.queries", False),
        ("observed-hash-log-reversed", "key :: out.queries", "out.queries ++ [key]", False),
        ("observed-hash-log-erase-prior", "key :: out.queries", "[key]", False),
        ("observed-hash-log-key", "key :: out.queries", "[] :: out.queries", False),
        ("observed-hash-log-equivalent", "key :: out.queries", "[key] ++ out.queries", True)]:
        add(name, key, old, new, check, expected)
    observed_cases("ObservedSession", "observeSign", "ObservedSession", "observe_sign_some", [
        ("observed-sign-log-drop", "⟨req, sig⟩ :: out.exposures", "out.exposures"),
        ("observed-sign-log-reversed", "⟨req, sig⟩ :: out.exposures", "out.exposures ++ [⟨req, sig⟩]"),
        ("observed-sign-log-erase-prior", "⟨req, sig⟩ :: out.exposures", "[⟨req, sig⟩]"),
        ("observed-sign-log-message", "⟨req, sig⟩ :: out.exposures", "⟨{ req with message := [] }, sig⟩ :: out.exposures"),
        ("observed-sign-log-randomizer", "⟨req, sig⟩ :: out.exposures", "⟨req, { sig with randomizer := 0 }⟩ :: out.exposures"),
        ("observed-sign-log-equivalent", "⟨req, sig⟩ :: out.exposures", "[⟨req, sig⟩] ++ out.exposures", True)])
    observed_cases("ObservedSession", "observeSign", "ObservedSession", "observe_sign_none", [
        ("observed-sign-none-clears-history", "| none => out", "| none => { out with exposures := [] }")])
    observed_cases("ObservedSession", "c10ObservedSession", "ObservedSession", "c10_observed_session_erases", [
        ("observed-session-done-cap", "⟨value, ledger, qr, qs⟩", "⟨value, ledger, qr + 1, qs⟩"),
        ("observed-session-raw-refusal-reply", "(next 0) 0 qs ledger table", "(next 1) 0 qs ledger table"),
        ("observed-session-raw-private", "encode (.inl key)", "encode (.inr key)"),
        ("observed-session-raw-reply", "(next reply.1) qr qs ledger reply.2", "(next 0) qr qs ledger reply.2"),
        ("observed-session-raw-cache", "(next reply.1) qr qs ledger reply.2", "(next reply.1) qr qs ledger table"),
        ("observed-session-sign-admission", "if sessionAdmits ledger req then", "if true then"),
        ("observed-session-sign-cap", "(next reply.1) qr qs\n", "(next reply.1) qr (qs + 1)\n"),
        ("observed-session-sign-reply", "(next reply.1) qr qs\n", "(next none) qr qs\n"),
        ("observed-session-sign-history", "(sessionAfterSign ledger req.message reply.1) reply.2", "ledger reply.2"),
        ("observed-session-sign-cache", "(sessionAfterSign ledger req.message reply.1) reply.2", "(sessionAfterSign ledger req.message reply.1) table"),
        ("observed-session-refused-spends", "(next none) qr (qs + 1) ledger table", "(next none) qr qs ledger table"),
        ("observed-session-admission-equivalent", "if sessionAdmits ledger req then", "if (fun b : Bool => b) (sessionAdmits ledger req) then", True)])
    observed_cases("ObservedSession", "c10ObservedSession", "ObservedExamples", "observed_repeated_hash", [
        ("observed-session-raw-not-logged", "observeHash key out.1", "out.1"),
        ("observed-session-raw-log-wrong-key", "observeHash key out.1", "observeHash [] out.1")])
    observed_cases("ObservedDriver", "c10ObservedDriver", "ObservedDriver", "c10_observed_driver_erases", [
        ("observed-driver-cap-swap", "client qr qs emptySessionLedger", "client qs qr emptySessionLedger"),
        ("observed-driver-final-cache-reset", "observed.1.session observed.2", "observed.1.session table"),
        ("observed-driver-result-flip", "⟨observed.1, result.1⟩", "⟨observed.1, !result.1⟩"),
        ("observed-driver-output-cache", "⟨observed.1, result.1⟩, result.2", "⟨observed.1, result.1⟩, table")])
    observed_cases("ObservedGame", "c10ObservedGame", "ObservedGame", "c10_observed_game_erases", [
        ("observed-game-keygen-reset", "encode table publicSeed", "encode (fun _ => none) publicSeed"),
        ("observed-game-client-key-swap", "adversary key.1.1 key.1.2", "adversary key.1.2 key.1.1"),
        ("observed-game-session-cache-reset", "qr qs key.2", "qr qs table"),
        ("observed-game-output-cache-reset", "(⟨key.1, out.1⟩, out.2)", "(⟨key.1, out.1⟩, table)")])
    observed_cases("ObservedGame", "c10ObservedGame", "ObservedGame", "c10_observed_game_keygen", [
        ("observed-game-recorded-key-swap", "⟨key.1, out.1⟩", "⟨(key.1.2, key.1.1), out.1⟩")])
    observed_cases("ObservedInitialized", "c10ObservedInitializedShared", "ObservedInitialized",
                   "c10_observed_initialized_shared_erases", [
        ("observed-initial-secret-fixed", "prefixedPrivateInput secret", "prefixedPrivateInput 0"),
        ("observed-initial-public-seed-fixed", "cfg input.1 input.2", "cfg 0 input.2"),
        ("observed-initial-cache-populated", "(fun _ => none)", "(fun _ => some 0)")])
    observed_cases("ObservedInitialized", "c10ObservedInitializedIndependent", "ObservedInitialized",
                   "c10_observed_initialized_independent_erases", [
        ("observed-independent-cap-swap", "input.2 qr qs", "input.2 qs qr"),
        ("observed-independent-cache-populated", "(fun _ => none)", "(fun _ => some 0)")])
    observed_cases("VerifierWitness", "VerificationWitness", "VerifierWitness", "verifier_witness_replay", [
        ("observed-verifier-hmsg-key-swap", "hmsgRandomizerInput seed root message", "hmsgRandomizerInput root seed message"),
        ("observed-verifier-forgot-acceptance", "forsAccept (forsOfDigest digest) = true", "True"),
        ("observed-verifier-forest-index", "(hypertreeIndex digest)\n      digest", "0\n      digest"),
        ("observed-verifier-layer-order", "sig.layers 2 0", "sig.layers 2 1"),
        ("observed-verifier-root-compare", "nodeBlock top = root", "nodeBlock top = seed")])
    observed_cases("RecoveryWitness", "WotsRecoveryWitness", "RecoveryWitness", "wots_witness_replay", [
        ("observed-wots-rejected-nonzero", "pk = 0", "pk = 1"),
        ("observed-wots-count-input", "message count))", "message (count + 1)))"),
        ("observed-wots-compression-address", "wotsCompressProgram seed layer tree kp values",
         "wotsCompressProgram seed (layer + 1) tree kp values")])

    observed_cases("ObservedSession", "c10ObservedSession", "ObservedBranches", "c10_observed_sign_returned", [
        ("observed-session-sign-not-logged", "observeSign req reply.1 out.1", "out.1"),
        ("observed-session-sign-request-changed", "observeSign req reply.1 out.1",
         "observeSign { req with message := [] } reply.1 out.1")])
    observed_cases("ObservedDriver", "c10ObservedDriver", "ObservedDriver", "c10_observed_driver_accounting", [
        ("observed-driver-exposures-cleared", "⟨observed.1, result.1⟩",
         "⟨{ observed.1 with exposures := [] }, result.1⟩"),
        ("observed-driver-queries-cleared", "⟨observed.1, result.1⟩",
         "⟨{ observed.1 with queries := [] }, result.1⟩")])

    # Actual tree certificates and recovery bindings. Keep earlier fixtures
    # byte-for-byte stable; these new slices also support inductive declarations.
    def tree_alias(module, name):
        match = re.search(r"^(?:def|abbrev|structure|inductive) " + re.escape(name) +
            r"\b.*?(?=^(?:theorem|def|abbrev|structure|inductive|end|attribute|set_option)\b)",
            src[module], flags=re.M | re.S)
        if not match:
            raise ValueError("missing tree binding definition " + name)
        alias = name + "BPCandidate"
        declaration = re.sub(r"\b" + re.escape(name) + r"\b", alias,
                             match.group(0).split("\n/--", 1)[0])
        key = alias + "Slice"
        src[key] = ("import C10Probability.TopTreeOpening\n"
            "import C10Probability.TreeCertificateExamples\n"
            "import C10Probability.TreeReferenceExamples\n"
            "namespace C10Probability\nnoncomputable section\n"
            "variable {K L R T α N S : Type*}\n" + declaration + "\nend\nend C10Probability\n")
        return key, alias

    def tree_consumer(module, name, definition, alias):
        check = theorem(src[module], name).split("\nset_option", 1)[0]
        return re.sub(r"\b" + re.escape(definition) + r"\b", alias, check)

    def tree_cases(module, definition, consumer_module, consumer, rows):
        key, alias = tree_alias(module, definition)
        check = tree_consumer(consumer_module, consumer, definition, alias)
        if definition == "replayMerge":
            check = """theorem checked :
    replayMergeBPCandidate certificateTable certificatePairKey id certificateRemember
      3 [(3, 0), (7, 1)] 0 4 [(1, 0, 1, 2)] =
    (replayProgram certificateTable (mergeProgram certificatePairKey id certificateRemember
      3 [0, 1] 0 (3, (7, PUnit.unit)) 4 [(1, 0, 1, 2)])).map
        (eraseTreeState (mergedShape 0 [0, 1])) := by
  rw [replay_merge_program]
  simp only [eraseStack]
  rfl
"""
        if definition == "replayTree":
            check = """theorem checked :
    replayTreeBPCandidate certificateTable (fun kp => some (kp + 1))
      certificatePairKey id certificateRemember 3 0 [] [] =
    (replayProgram certificateTable (treeProgram 0 certificateLeafProgram
      certificatePairKey id certificateRemember 3 0 [] PUnit.unit [])).map
        (eraseTreeState (runShape 3 [])) := by
  rw [replay_tree_program]
  simp only [eraseStack]
  rfl
"""
        for row in rows:
            consumer_check = check
            if row[0] == "tree-opening-reference-absent":
                # Consume the reference link. A producer of a weakened opening
                # can still succeed after replacing its reference proof by True.intro.
                consumer_check = """theorem checked (encode : WotsQuery → K) (table : Memo K Digest)
    (seed root message : ByteKey) (sig : C10Signature)
    (opening : TopTreeOpeningBPCandidate encode table seed root message sig) :
    ∃ digest middle leaf,
      table (encode (.inl (hmsgRandomizerInput seed root message sig.randomizer))) = some digest ∧
      replayProgram table (wotsRecoveryUnderProgram (fun key => encode (.inl key)) seed 1 0
        (hypertreeLeaf (hypertreeParent (hypertreeIndex digest))) (nodeValueBytes middle)
        ((sig.layers[1]?).getD emptyLayerSignature).sigma
        ((sig.layers[1]?).getD emptyLayerSignature).count) = some leaf ∧
      replayProgram table (wotsLeafProgram encode seed 1 0
        (hypertreeLeaf (hypertreeParent (hypertreeIndex digest)))) = some leaf := by
  obtain ⟨digest, forest, middle, top, leaf, countDigest, hd, ha, hf, hm, hw, hp, hl, hc, accepted, he⟩ := opening
  exact ⟨digest, middle, leaf, hd, hw, hl⟩
"""
            add(row[0], key, row[1], row[2], consumer_check, row[3] if len(row) == 4 else False)

    tree_cases("TreeReplay", "replayMerge", "TreeReplay", "replay_merge_program", [
        ("tree-replay-parent-absent", "(table (input kp height left current)).bind", "(none : Option α).bind"),
        ("tree-replay-parent-order", "input kp height left current", "input kp height current left"),
        ("tree-replay-height-branch", "if level = height then", "if level ≠ height then"),
        ("tree-replay-parent-coordinate", "input kp height left current", "input (kp + 1) height left current"),
        ("tree-replay-height-jump", "rest (height + 1)", "rest (height + 2)"),
        ("tree-replay-parent-value", "(project reply) (remember", "current (remember"),
        ("tree-replay-remember-lost", "(remember kp height left current state)", "state"),
        ("tree-replay-final-height", "some ([(current, height)], state)", "some ([(current, height + 1)], state)"),
        ("tree-replay-merge-equivalent", "rest (height + 1)", "rest (height + 0 + 1)", True)])
    tree_cases("TreeReplay", "replayTree", "TreeReplay", "replay_tree_program", [
        ("tree-replay-leaf-coordinate", "(leaf start).bind", "(leaf (start + 1)).bind"),
        ("tree-replay-repeat-leaf", "n (start + 1)", "n start"),
        ("tree-replay-prior-lost", "remember start stack 0", "remember start [] 0"),
        ("tree-replay-state-lost", "merged.1 merged.2", "merged.1 state"),
        ("tree-replay-merged-lost", "merged.1 merged.2", "stack merged.2"),
        ("tree-replay-base-lost", "some (stack, state)", "some ([], state)"),
        ("tree-replay-leaf-equivalent", "n (start + 1)", "n (start + 0 + 1)", True)])

    key, alias = tree_alias("TreeCertificate", "RecordedTreeNode")
    leaf_check = """theorem checked (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (edge : ℕ) (root : N)
    (recorded : RecordedTreeNodeBPCandidate table leaf input project 0 edge root) :
    ∃ kp, edge = kp + 1 ∧ leaf kp = some root := by
  cases recorded <;> exact ⟨_, rfl, by assumption⟩
"""
    add("tree-certificate-leaf-evidence", key, "leaf kp = some value", "True", leaf_check)
    add("tree-certificate-leaf-coordinate", key, "0 (kp + 1) value", "0 kp value", leaf_check)
    pair_check = """theorem checked (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (height edge : ℕ) (root : N)
    (recorded : RecordedTreeNodeBPCandidate table leaf input project (height + 1) edge root) :
    ∃ left right reply,
      RecordedTreeNodeBPCandidate table leaf input project height (edge - 2 ^ height) left ∧
      RecordedTreeNodeBPCandidate table leaf input project height edge right ∧
      table (input (edge - 1) height left right) = some reply ∧ root = project reply := by
  cases recorded with
  | pair h e l r d hl hr hd => exact ⟨l, r, d, hl, hr, hd, rfl⟩
"""
    for name, old, new in [
        ("tree-certificate-left-edge", "height (edge - 2 ^ height) left", "height edge left"),
        ("tree-certificate-right-edge", "height edge right", "height (edge + 1) right"),
        ("tree-certificate-parent-coordinate", "input (edge - 1) height left right", "input edge height left right"),
        ("tree-certificate-parent-height", "input (edge - 1) height left right", "input (edge - 1) (height + 1) left right"),
        ("tree-certificate-parent-order", "input (edge - 1) height left right", "input (edge - 1) height right left")]:
        add(name, key, old, new, pair_check)

    key, alias = tree_alias("TreeCertificate", "RecordedForest")
    check = """theorem checked (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (edge height : ℕ) (root : N) (rest : List (N × ℕ))
    (recorded : RecordedForestBPCandidate table leaf input project edge ((root, height) :: rest)) :
    RecordedTreeNode table leaf input project height edge root ∧
      RecordedForestBPCandidate table leaf input project (edge - 2 ^ height) rest := by
  exact recorded
"""
    for name, old, new in [
        ("tree-forest-head-lost", "RecordedTreeNode table leaf input project height edge root ∧", "True ∧"),
        ("tree-forest-tail-edge", "(edge - 2 ^ height) rest", "edge rest"),
        ("tree-forest-head-height", "project height edge root ∧", "project (height + 1) edge root ∧")]:
        add(name, key, old, new, check)

    tree_cases("PathReplay", "replayPath", "PathRecovery", "recovery_program_replay_path", [
        ("tree-path-lookup-absent", "(table (pathPairInput pair height index current sibling)).bind", "(none : Option α).bind"),
        ("tree-path-height", "(height + 1) (index / 2)", "height (index / 2)"),
        ("tree-path-parent-index", "(height + 1) (index / 2)", "(height + 1) index"),
        ("tree-path-parent-value", "(project reply) rest", "current rest"),
        ("tree-path-suffix-lost", "replayPathBPCandidate table pair project (height + 1) (index / 2) (project reply) rest", "some (project reply)"),
        ("tree-path-step-equivalent", "(height + 1) (index / 2)", "(height + 0 + 1) (index / 2)", True)])
    key, alias = tree_alias("PathReplay", "pathPairInput")
    check = """theorem checked (seed : ByteKey) (layer tree height index : ℕ)
    (current : Randomizer) (auth : List Randomizer) :
    pathPairInputBPCandidate (merklePairInput seed layer tree) height index current
      ((auth[height]?).getD 0) = recoveryInput seed layer tree height index auth current := by
  by_cases h : index % 2 = 0 <;> simp only [pathPairInputBPCandidate, recoveryInput, h, ↓reduceIte]
"""
    for name, old, new in [
        ("tree-path-parity", "if index % 2 = 0 then", "if index % 2 = 1 then"),
        ("tree-path-even-parent", "then pair height (index / 2)", "then pair height index"),
        ("tree-path-odd-order", "else pair height (index / 2) sibling current", "else pair height (index / 2) current sibling")]:
        add(name, key, old, new, check)
    tree_cases("PathRecovery", "pathSiblings", "PathRecovery", "recovery_program_replay_path", [
        ("tree-path-sibling-index", "(auth[height]?).getD fallback", "(auth[height + 1]?).getD fallback"),
        ("tree-path-sibling-repeat", "steps (height + 1)", "steps height"),
        ("tree-path-sibling-default", "(auth[height]?).getD fallback", "fallback"),
        ("tree-path-sibling-equivalent", "steps (height + 1)", "steps (height + 0 + 1)", True)])
    tree_cases("TreeRootCertificate", "MerkleTreeCertificate", "TreeRootCertificate", "replay_subtree_root_certificate", [
        ("tree-merkle-certificate-height", "randomizerOfDigest 9 512 root", "randomizerOfDigest 8 512 root"),
        ("tree-merkle-certificate-leaf-count", "randomizerOfDigest 9 512 root", "randomizerOfDigest 9 511 root"),
        ("tree-merkle-certificate-leaf-index", "wotsLeafProgram encode seed layer tree kp", "wotsLeafProgram encode seed layer tree (kp + 1)")])
    tree_cases("TreeRootCertificate", "ForsTreeCertificate", "TreeRootCertificate", "replay_fors_root_certificate", [
        ("tree-fors-certificate-height", "randomizerOfDigest 11 2048 root", "randomizerOfDigest 10 2048 root"),
        ("tree-fors-certificate-leaf-count", "randomizerOfDigest 11 2048 root", "randomizerOfDigest 11 2047 root"),
        ("tree-fors-certificate-leaf-index", "forsLeafProgram encode seed ht tree kp", "forsLeafProgram encode seed ht tree (kp + 1)")])
    tree_cases("NodePathBinding", "PublicNodeCollisionFree", "NodePathBinding", "merkle_path_leaf_eq", [
        ("tree-binding-selection-empty", "selectedCache nodeQuery", "selectedCache (fun _ => false)"),
        ("tree-binding-cache-empty", "fun key => table (encode key)", "fun (_ : ByteKey) => (none : Option Digest)"),
        ("tree-binding-wrong-projection", "CollisionFree randomizerOfDigest", "CollisionFree (fun (d : Digest) => (⟨d.val % 2 ^ 128, Nat.mod_lt _ (by decide)⟩ : Randomizer))")])
    tree_cases("TopTreeOpening", "TopTreeOpening", "TopTreeOpening", "verifier_top_tree_opening", [
        ("tree-opening-hmsg-key", "hmsgRandomizerInput seed root message", "hmsgRandomizerInput root seed message"),
        ("tree-opening-forest-coordinate", "(hypertreeIndex digest) digest sig.secrets", "0 digest sig.secrets"),
        ("tree-opening-lower-layer", "seed 0\n", "seed 1\n"),
        ("tree-opening-top-signature", "((sig.layers[1]?).getD emptyLayerSignature).sigma", "((sig.layers[0]?).getD emptyLayerSignature).sigma"),
        ("tree-opening-reference-absent", "replayProgram table (wotsLeafProgram encode seed 1 0\n      (hypertreeLeaf (hypertreeParent (hypertreeIndex digest)))) = some leaf", "True"),
        ("tree-opening-reference-cache", "replayProgram table (wotsLeafProgram", "replayProgram (fun _ => none) (wotsLeafProgram"),
        ("tree-opening-count-message", "wotsRecoverCountInput seed 1 0\n      (hypertreeLeaf (hypertreeParent (hypertreeIndex digest))) (nodeValueBytes middle)", "wotsRecoverCountInput seed 1 0\n      (hypertreeLeaf (hypertreeParent (hypertreeIndex digest))) message"),
        ("tree-opening-count-acceptance", "wotsAccept (wotsOfDigest countDigest) = true", "wotsAccept (wotsOfDigest countDigest) = false"),
        ("tree-opening-root-comparison", "nodeBlock top = root", "nodeBlock top = seed"),
        ("tree-opening-reference-layer", "wotsLeafProgram encode seed 1 0", "wotsLeafProgram encode seed 0 0")])

    # WOTS chain openings and actual signing witnesses. The three predicate
    # consumers retain the complete original claim, so deleting a conjunct
    # cannot pass merely because a weaker producer still has a proof.
    def bq_alias(module, name):
        match = re.search(r"^(?:def|abbrev|structure|inductive) " + re.escape(name) +
            r"\b.*?(?=^(?:theorem|def|abbrev|structure|inductive|end|attribute|set_option)\b)",
            src[module], flags=re.M | re.S)
        if not match:
            raise ValueError("missing WOTS binding definition " + name)
        declaration = match.group(0).split("\n/--", 1)[0]
        alias = name + "BQCandidate"
        key = alias + "Slice"
        src[key] = ("import C10Probability.ObservedChains\n"
            "import C10Probability.LayerPrefixComparison\n"
            "import C10Probability.ChainBindingExamples\n"
            "import C10Probability.WotsOpeningExamples\n"
            "namespace C10Probability\nnoncomputable section\n"
            "variable {I K L R T α β N S : Type*}\n" +
            re.sub(r"\b" + re.escape(name) + r"\b", alias, declaration) +
            "\nend\nend C10Probability\n")
        return key, alias, declaration

    key, alias, declaration = bq_alias("TopChainOpening", "TopChainOpening")
    check = """theorem checked (encode : WotsQuery → K) (table : Memo K Digest)
    (seed root message : ByteKey) (sig : C10Signature)
    (opening : TopChainOpeningBQCandidate encode table seed root message sig) :
    TopChainOpening encode table seed root message sig := by
  exact opening
"""
    tail = declaration[declaration.index("∀ i, replayProgram table (wotsSeedChainProgram"):].rstrip()
    for row in [
        ("wots-opening-hmsg-input", "hmsgRandomizerInput seed root message", "hmsgRandomizerInput root seed message"),
        ("wots-opening-fors-acceptance-absent", "forsAccept (forsOfDigest digest) = true", "True"),
        ("wots-opening-forest-coordinate", "(hypertreeIndex digest) digest sig.secrets", "0 digest sig.secrets"),
        ("wots-opening-lower-layer", "seed 0\n", "seed 1\n"),
        ("wots-opening-recovered-signature", "((sig.layers[1]?).getD emptyLayerSignature).sigma\n", "((sig.layers[0]?).getD emptyLayerSignature).sigma\n"),
        ("wots-opening-reference-absent", "replayProgram table (wotsLeafProgram encode seed 1 0\n      (hypertreeLeaf (hypertreeParent (hypertreeIndex digest)))) = some leaf", "True"),
        ("wots-opening-count-acceptance-absent", "wotsAccept (wotsOfDigest countDigest) = true", "True"),
        ("wots-opening-root-compare", "nodeBlock top = root", "nodeBlock top = seed"),
        ("wots-opening-prefixes-absent", tail, "True"),
        ("wots-opening-prefix-cache", "∀ i, replayProgram table", "∀ i, replayProgram (fun _ => none)"),
        ("wots-opening-prefix-coordinate", "(hypertreeLeaf (hypertreeParent (hypertreeIndex digest))) i.val", "(hypertreeLeaf (hypertreeParent (hypertreeIndex digest)) + 1) i.val"),
        ("wots-opening-prefix-index", "))) i.val\n", "))) 0\n"),
        ("wots-opening-prefix-digit", "(wotsOfDigest countDigest i).val", "((wotsOfDigest countDigest i).val + 1)"),
        ("wots-opening-prefix-submitted-value", "some (((sig.layers[1]?).getD emptyLayerSignature).sigma i)", "some (((sig.layers[1]?).getD emptyLayerSignature).sigma 0)"),
        ("wots-opening-digit-equivalent", "(wotsOfDigest countDigest i).val", "((wotsOfDigest countDigest i).val + 0)", True),
        ("wots-opening-position-equivalent", "some (((sig.layers[1]?).getD emptyLayerSignature).sigma i)", "some (((sig.layers[1]?).getD emptyLayerSignature).sigma (id i))", True)]:
        add(row[0], key, row[1], row[2], check, row[3] if len(row) == 4 else False)

    key, alias, declaration = bq_alias("LayerSigningReplay", "LayerChainWitness")
    check = """theorem checked (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (sig : LayerSignature) (root : Randomizer)
    (witness : LayerChainWitnessBQCandidate encode table seed layer tree leaf message shuffle n bound sig root) :
    LayerChainWitness encode table seed layer tree leaf message shuffle n bound sig root := by
  exact witness
"""
    tail = declaration[declaration.index("∀ i, replayProgram table (wotsSeedChainProgram"):].rstrip()
    for row in [
        ("wots-layer-signing-absent", "replayProgram table (layerSignProgram encode seed layer tree leaf message shuffle n bound) =\n    some (some (sig, root))", "True"),
        ("wots-layer-signing-cache", "replayProgram table (layerSignProgram", "replayProgram (fun _ => none) (layerSignProgram"),
        ("wots-layer-shuffle-coordinate", "shuffle (layerShuffleLabel layer)", "shuffle (layerShuffleLabel (layer + 1))"),
        ("wots-layer-shuffle-result", "= some subseed ∧", "= some [] ∧"),
        ("wots-layer-signed-message", "wotsSignProgram encode seed layer tree leaf\n      (nodeValueBytes message)", "wotsSignProgram encode seed layer tree leaf\n      []"),
        ("wots-layer-returned-values", "some (some (sig.sigma, sig.count))", "some (some ((fun _ => 0), sig.count))"),
        ("wots-layer-count-message", "wotsCountProgram seed layer tree leaf (nodeValueBytes message)", "wotsCountProgram seed layer tree leaf (nodeValueBytes 0)"),
        ("wots-layer-count-result", "some (some (sig.count, digest))", "some (some (0, digest))"),
        ("wots-layer-acceptance-absent", "wotsAccept (wotsOfDigest digest) = true", "True"),
        ("wots-layer-prefixes-absent", tail, "True"),
        ("wots-layer-prefix-index", "seed layer tree leaf i.val", "seed layer tree leaf 0"),
        ("wots-layer-prefix-digit", "(wotsOfDigest digest i).val", "7"),
        ("wots-layer-digit-equivalent", "(wotsOfDigest digest i).val", "((wotsOfDigest digest i).val + 0)", True)]:
        add(row[0], key, row[1], row[2], check, row[3] if len(row) == 4 else False)

    key, alias, declaration = bq_alias("C10SigningReplay", "C10ChainWitness")
    check = """theorem checked (encode : WotsQuery → K) (table : Memo K Digest)
    (random message seed root shuffle : ByteKey) (m n : ℕ)
    (rBound : m ≤ 2 ^ 32) (wBound : n ≤ 2 ^ 32) (sig : C10Signature)
    (witness : C10ChainWitnessBQCandidate encode table random message seed root shuffle m n rBound wBound sig) :
    C10ChainWitness encode table random message seed root shuffle m n rBound wBound sig := by
  exact witness
"""
    for row in [
        ("wots-c10-r-message", "randomizerUnderProgram encode random message seed root", "randomizerUnderProgram encode random root seed root"),
        ("wots-c10-r-value", "some (some (trial, sig.randomizer, digest))", "some (some (trial, 0, digest))"),
        ("wots-c10-r-digest", "some (some (trial, sig.randomizer, digest))", "some (some (trial, sig.randomizer, 0))"),
        ("wots-c10-forest-absent", "replayProgram table (forestSignProgram encode seed (hypertreeIndex digest) digest shuffle) = some forest", "(forest : ForestOutput) = forest"),
        ("wots-c10-forest-cache", "replayProgram table (forestSignProgram", "replayProgram (fun _ => none) (forestSignProgram"),
        ("wots-c10-secrets-absent", "sig.secrets = forest.secrets", "True"),
        ("wots-c10-auths-absent", "sig.auths = forest.auths", "True"),
        ("wots-c10-layers-reversed", "sig.layers = [lower, upper]", "sig.layers = [upper, lower]"),
        ("wots-c10-layers-absent", "sig.layers = [lower, upper]", "True"),
        ("wots-c10-lower-coordinate", "(hypertreeLeaf (hypertreeIndex digest)) forest.pk", "0 forest.pk"),
        ("wots-c10-upper-coordinate", "seed 1 0 (hypertreeLeaf (hypertreeParent (hypertreeIndex digest)))", "seed 1 0 0"),
        ("wots-c10-upper-message", "middle shuffle n wBound upper top", "forest.pk shuffle n wBound upper top"),
        ("wots-c10-layer-list-equivalent", "sig.layers = [lower, upper]", "sig.layers = lower :: upper :: []", True)]:
        add(row[0], key, row[1], row[2], check, row[3] if len(row) == 4 else False)

    key, alias, declaration = bq_alias("NodePathBinding", "PublicNodeCollisionFree")
    check = re.sub(r"\bPublicNodeCollisionFree\b", alias,
                   theorem(src["WotsChainBinding"], "replay_wots_chain_start_eq"))
    for name, old, new in [
        ("wots-chain-collision-domain-empty", "selectedCache nodeQuery", "selectedCache (fun _ => false)"),
        ("wots-chain-collision-cache-empty", "fun key => table (encode key)", "fun (_ : ByteKey) => (none : Option Digest)"),
        ("wots-chain-collision-projection", "CollisionFree randomizerOfDigest", "CollisionFree (fun (d : Digest) => (⟨d.val % 2 ^ 128, Nat.mod_lt _ (by decide)⟩ : Randomizer))")]:
        add(name, key, old, new, check)

    key, alias, declaration = bq_alias("WotsChain", "wotsChainInput")
    check = re.sub(r"\bwotsChainInput\b", alias,
                   theorem(src["ChainBindingExamples"], "binding_wots_chain_node_changes_input"))
    add("wots-chain-binding-node-absent", key, "randomizerBytesEquiv.symm current",
        "randomizerBytesEquiv.symm 0", check)
    key, alias, declaration = bq_alias("WotsPrivate", "wotsSeedChainProgram")
    src[key] = src[key].replace("noncomputable section\n",
        "noncomputable section\nset_option maxRecDepth 4096\n")
    check = re.sub(r"\bwotsSeedChainProgram\b", alias,
                   theorem(src["WotsOpeningExamples"], "opening_zero_cut_uses_private_reply"))
    add("wots-chain-private-route-lost", key, "encode (.inr (wotsPrivateTail", "encode (.inl (wotsPrivateTail", check)

    # Actual returned authentication arrays: typed predicate consumers and
    # asymmetric execution vectors. Baseline/definition/consumer are separate.
    def br_alias(module, name):
        match = re.search(r"^(?:def|abbrev) " + re.escape(name) +
            r"\b.*?(?=^(?:theorem|def|abbrev|structure|inductive|end|attribute|set_option)\b)",
            src[module], flags=re.M | re.S)
        if not match:
            raise ValueError("missing returned-auth definition " + name)
        declaration = match.group(0).split("\n/--", 1)[0]
        alias = name + "BRCandidate"
        key = alias + "Slice"
        src[key] = ("import C10Probability.AuthPathExamples\n"
            "namespace C10Probability\nnoncomputable section\n"
            "variable {K α N S : Type*}\n" +
            re.sub(r"\b" + re.escape(name) + r"\b", alias, declaration) +
            "\nend\nend C10Probability\n")
        return key, alias, declaration

    key, alias, declaration = br_alias("AuthCertificate", "RecordedAuthSlot")
    check = """theorem checked (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (target : ℕ) (auth : List N) (height : ℕ)
    (slot : RecordedAuthSlotBRCandidate table leaf input project target auth height) :
    RecordedAuthSlot table leaf input project target auth height := by
  exact slot
"""
    for row in [
        ("auth-slot-stored-index", "auth[height]?", "auth[0]?"),
        ("auth-slot-stored-value-absent", "auth[height]? = some value", "True"),
        ("auth-slot-node-absent", "RecordedTreeNode table leaf input project\n    height ((siblingIndex (target / 2 ^ height) + 1) * 2 ^ height) value", "True"),
        ("auth-slot-target", "siblingIndex (target / 2 ^ height)", "siblingIndex (0 / 2 ^ height)"),
        ("auth-slot-sibling", "siblingIndex (target / 2 ^ height)", "(target / 2 ^ height)"),
        ("auth-slot-edge", "+ 1) * 2 ^ height", "+ 0) * 2 ^ height"),
        ("auth-slot-cache", "RecordedTreeNode table leaf", "RecordedTreeNode (fun _ => none) leaf"),
        ("auth-slot-index-equivalent", "auth[height]?", "auth[height + 0]?", True)]:
        add(row[0], key, row[1], row[2], check, row[3] if len(row) == 4 else False)

    key, alias, declaration = br_alias("AuthCertificate", "CollectedTreeNode")
    check = """theorem checked (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (target : ℕ) (auth : List N) (height edge : ℕ) (root : N)
    (node : CollectedTreeNodeBRCandidate table leaf input project target auth height edge root) :
    CollectedTreeNode table leaf input project target auth height edge root := by
  exact node
"""
    tail = declaration[declaration.index("(edge - 2 ^ height ≤ target"):].rstrip()
    for row in [
        ("auth-node-root-absent", "RecordedTreeNode table leaf input project height edge root", "True"),
        ("auth-node-path-absent", tail, "True"),
        ("auth-node-last-slot-omitted", "j < height →", "j < height - 1 →"),
        ("auth-node-slots-other-array", "target auth j", "target [] j"),
        ("auth-node-slots-other-target", "target auth j", "0 auth j")]:
        add(row[0], key, row[1], row[2], check)

    key, alias, declaration = br_alias("AuthKeepLaw", "AuthKeepValid")
    check = """theorem checked (table : Memo K α) (leaf : ℕ → Option Randomizer)
    (input : ℕ → ℕ → Randomizer → Randomizer → K) (project : α → Randomizer)
    (target bound : ℕ) (state : AuthKeep)
    (valid : AuthKeepValidBRCandidate table leaf input project target bound state) :
    AuthKeepValid table leaf input project target bound state := by
  exact valid
"""
    tail = declaration[declaration.index("∀ j,"):].rstrip()
    for row in [
        ("auth-keep-node-length-absent", "state.nodes.length = bound", "True"),
        ("auth-keep-flag-length-absent", "state.kept.length = bound", "True"),
        ("auth-keep-soundness-absent", tail, "True"),
        ("auth-keep-flag-polarity", ".getD false = true", ".getD false = false"),
        ("auth-keep-other-node-array", "target state.nodes j", "target [] j")]:
        add(row[0], key, row[1], row[2], check)

    for name, arguments, height, leaf_program in [
        ("MerkleAuthCertificate", "layer tree", "9", "wotsLeafProgram encode seed layer tree kp"),
        ("ForsAuthCertificate", "ht tree", "11", "forsLeafProgram encode seed ht tree kp")]:
        key, alias, declaration = br_alias("ReturnedAuth", name)
        check = ("theorem checked (encode : WotsQuery → K) (table : Memo K Digest)\n"
            "    (seed : ByteKey) (" + arguments + " target : ℕ) (auth : List Randomizer) (root : Randomizer)\n"
            "    (cert : " + alias + " encode table seed " + arguments + " target auth root) :\n"
            "    " + name + " encode table seed " + arguments + " target auth root := by\n  exact cert\n")
        prefix = "auth-merkle" if height == "9" else "auth-fors"
        for row in [
            (prefix + "-length-absent", "auth.length = " + height, "True"),
            (prefix + "-leaf-coordinate", leaf_program, leaf_program[:-2] + "0"),
            (prefix + "-returned-target", "randomizerOfDigest target auth", "randomizerOfDigest 0 auth"),
            (prefix + "-returned-array", "randomizerOfDigest target auth", "randomizerOfDigest target []"),
            (prefix + "-certificate-cache", "CollectedTreeNode table", "CollectedTreeNode (fun _ => none)"),
            (prefix + "-array-equivalent", "randomizerOfDigest target auth", "randomizerOfDigest target (id auth)", True)]:
            add(row[0], key, row[1], row[2], check, row[3] if len(row) == 4 else False)

    key, alias, declaration = br_alias("AuthGeometry", "collectAuth")
    check = theorem(src["AuthPathExamples"], "four_leaf_fors_returned_paths").replace("forsRemember", alias)
    for row in [
        ("auth-collector-left-value", "auth.set height left", "auth.set height right"),
        ("auth-collector-right-value", "auth.set height right", "auth.set height left"),
        ("auth-collector-left-slot", "auth.set height left", "auth.set (height + 1) left"),
        ("auth-collector-right-slot", "auth.set height right", "auth.set (height + 1) right"),
        ("auth-collector-right-coordinate", "+ 1 = siblingIndex", "+ 0 = siblingIndex"),
        ("auth-collector-right-write-absent", "auth.set height right", "auth"),
        ("auth-collector-left-equivalent", "auth.set height left", "auth.set (height + 0) left", True)]:
        add(row[0], key, row[1], row[2], check, row[3] if len(row) == 4 else False)

    key, alias, declaration = br_alias("MerkleBuild", "authRemember")
    check = theorem(src["AuthPathExamples"], "initially_kept_path_fails").replace("authRemember", alias)
    add("auth-kept-check-ignored", key, "if (state.kept[height]?).getD false then state",
        "if false then state", check)

    key, alias, declaration = br_alias("MerkleBuild", "writeAuthKeep")
    check = """theorem checked :
    (writeAuthKeepBRCandidate ⟨[1, 2], [false, false]⟩ 1 7).nodes = [1, 7] ∧
    (writeAuthKeepBRCandidate ⟨[1, 2], [false, false]⟩ 1 7).kept = [false, true] := by decide +kernel
"""
    add("auth-written-flag-lost", key, "state.kept.set height true", "state.kept.set height false", check)
    add("auth-written-node-lost", key, "state.nodes.set height node", "state.nodes", check)

    return out
