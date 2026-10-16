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
    return out
