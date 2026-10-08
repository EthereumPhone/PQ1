# Actual-output WOTS reverse-chain and encoding charges

This extends the [ordinary FORS opening charge](RAW-SELECTIVE-HIDING.md) in the
manual classical ideal-oracle model. It bounds new WOTS component messages in
the **actual accepted byte output**, using the original initialized adaptive
hash/sign game. It does not assert complete EUF-CMA security.

`OriginalWotsBound.original_byte_new_wots_bound` proves

```
Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run :
  res /\ actual_new_wots_component(..., ClientQueryLog.output)]
 <= Q * (Q - 1) / (2 * 2^129)
    + 632475648 * (Q + 86) / 2^128

Q = full_public_budget(qr, qs)
  = 155135 + qr + qs * (3 * signing_budget + 364892) + 771
signing_budget = 10000000
```

The premises are nonnegative configured hash/sign caps and termination of the
client for lossless byte hash/sign oracles. Abstract-client exclusions keep
oracle tables and proof observers private. There is no assumed hidden-chain
independence or undisclosed transformed-budget premise. The verifier retains
the full 32-bit wire counter range; only honest count search is bounded by the
signing budget. These conservative constants do not claim a tight security level.

## Exact output and adaptive disclosure

`ActualExposurePartition` retains the submitted pair, its H_msg digest and
both verifier-layer witnesses. `MinimumExposureGame` and `QueryMinimumHistory`
prove that every successful returned signature uses the first accepted count.
`ForestRootUnique` and `CanonicalExposure` identify the fixed component message
at each WOTS address. Repeated signing at that address therefore has the same
accepted digit word and node vector; it does not expose additional lower cuts.
The returned-response ledger contains repeats and persists under later queries.
Failed signing makes the session absorbing, so an opening from a failed request
cannot be followed by an accepted final output.

For distinct accepted constant-sum words, a forged digit is below some honest
digit. Equal digit words on different public inputs fall under the separate
encoding-collision event. For an unsigned address, at least one forged digit
is below seven because the sum is 205, less than 43 times seven.
`ActualWotsCut` binds that cut to an actual node in the supplied signature;
it does not substitute an arbitrary existential witness for the submitted output.

`ObservedValueOpening` marks a selected-chain request at or below the selected
cut as an opening. Key generation and Merkle construction request the endpoint
at seven and do not open a proper cut. FORS and randomizer derivations use
disjoint private inputs. `ObservedSignerOpening`, `ObservedSessionOpening` and
`ObservedUnreturnedCut` prove that an unreturned selected cut on an accepted run
was never opened, using the actual successful-response ledger.

## Hiding and query accounting

The trusted internal chain interface returns the same concrete chain values.
`ChainContextCoupling` replaces an observed concrete chain by its precomputed
cache while preserving results and public/private tables. It deliberately does
not equate public query logs: cache hits remove internal hash calls.

`CompleteChainProgramming` connects that cache to eight independently sampled
full digests. For a cut from zero through six, a hidden vector supplies positions
at or below the cut and an independent visible vector supplies later positions.
The redacted program installs only the visible suffix. Its public-table relation
is preserved until a public input's final padded node slot matches a hidden
node. Adaptive openings are removed only on the unopened winning event.
`ProgrammedChainBound` charges public guesses plus final candidate nodes.

The hidden-vector union includes all eight entries, even though its last entry
is unused at proper cuts. This gives the conservative factor eight in
`SelectedWotsBound.selected_wots_original_bound`:

```
Pr[selected fixed-coordinate cut in the original game]
 <= 8 * (Q + 86) / 2^128.
```

The 86 candidates are all 43 WOTS nodes in both output layers. The
`Redacted*Cost` modules and `VisibleByteBudget` prove the transformed budget
through key generation, grinding, complete signing, session caps and final
verification, including repeated public calls. No computational secrecy
assumption is inferred merely from a value being absent from the return ledger.

Early/late memo sampling preserves the adaptive context. A selected event with
its retained complete chain reference permits late sampling without changing
that event. `OriginalWotsCoordinateBound` then chooses each fixed coordinate
before the game and relates it to one common unmodified candidate game.
`OriginalWotsUnion` performs the finite union in that game. The universe has
`(262144 + 512) * 43 * 7 = 79059456` bottom/top coordinates, giving the total
factor `79059456 * 8 = 632475648`. The seed is the actual fixed public-seed input;
there is no extra seed union or post hoc coordinate-dependent experiment.

## Encoding and certificate boundary

C10's 43 radix-eight digits read the low 129 digest bits. The node projection
reads the high 128 bits; its birthday theorem cannot substitute for this event.
`EncodingDistribution`, `EncodingBirthday` and `ByteEncodingCharge` prove the
separate memoized low-129-bit collision bound on the same original byte game.

Every new module is a replay target with statement/operation pins, source
bindings, declaration census and scope controls. The only new clone is
`DList.Program` instantiated with full digests using `proof *`; it adds no
unresolved clone premise. Paired controls check the cut boundary, all 86 output
positions, both coordinate layers and the 129-bit encoding width. Expected
rejections establish rejection of those attempts; they do not prove optimality
of the probability bound. See [control evidence](CONTROL-EVIDENCE.md).

No production signer or wire behavior changes. The model is manually
transcribed and classical, with a trusted pinned EasyCrypt/SMT toolchain.
Concrete SHA-256, QROM and Rust extraction are outside this result. The
[numerical continuation](RAW-NUMERICAL-EUF.md) supplies accumulated adaptive FORS
coverage and the final common-game composition. The older conditional MM45
capstone remains a separate theorem family.
