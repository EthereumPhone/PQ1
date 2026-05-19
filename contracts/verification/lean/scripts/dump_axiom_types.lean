/-
Audit script: prints every `axiom` declaration in the SphincsCVerify
project along with its elaborated type.

Run via:
  lake env lean scripts/dump_axiom_types.lean

The lint script `contracts/verification/scripts/lint_axioms.sh` parses
this output to detect axioms whose type reduces to `True` (placeholder
markers without semantic content). It is complementary to the existing
`dump_axioms.lean` (which prints the dep CLOSURE per theorem, but
hides each axiom's type).

The list of axioms is enumerated explicitly. The companion lint
script's source-pattern scan ensures any newly-introduced axiom in
`SphincsCVerify/` triggers a CI failure unless it is also added here
(forcing the author to acknowledge the new TCB item).
-/

import SphincsCVerify

-- Bridge axioms (A1, A3, A4) — currently `True`-typed placeholders.
#check @SphincsCVerify.Bridge.precompile_0x02_is_FIPS_180_4
#check @SphincsCVerify.Bridge.solidityVerifier_compiles_correctly
#check @SphincsCVerify.Bridge.evm_bytecode_executes_correctly

-- EntryPoint v0.6 axiom (A2) — has propositional content but states a
-- property of the Lean `handleOp` fiction, not the deployed contract.
#check @SphincsCVerify.Bridge.EntryPoint.entrypoint_honest

-- Cryptographic axioms (A5).
#check @SphincsCVerify.Crypto.EUF_CMA_SPHINCSplusC
#check @SphincsCVerify.Crypto.SM_DT_TCR_F
#check @SphincsCVerify.Crypto.ITSR_F
#check @SphincsCVerify.Crypto.hMsg_random_oracle

-- Shape-side definitions (Prop aliases). Their unfolded form is what
-- the lint script needs to see; #print surfaces the def body.
#print SphincsCVerify.Crypto.SM_DT_TCR_F_Shape
#print SphincsCVerify.Crypto.ITSR_F_Shape
#print SphincsCVerify.Crypto.hMsg_RO_Shape
