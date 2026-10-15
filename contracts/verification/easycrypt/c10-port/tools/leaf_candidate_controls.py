"""Ordinary FORS candidate controls. Finite pairs have explicit false alternatives;
probability/contract pairs test theorem sensitivity, not falsity of every mutant.
Literal claims do not silently adopt a changed implementation statement.
"""

CHECKS = [{'name': 'retain-zero',
  'kind': 'finite-counterexample',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount '
             'LeafCandidateMass LeafGrindingCandidates.\n',
  'positive': ': mem (leaf_reduced_candidates [] []) (nseq 16 0)',
  'negative': ': !(mem (leaf_reduced_candidates [] []) (nseq 16 0))',
  'proof': 'have h : mem (leaf_reduced_candidates [] []) (nseq 16 0) by rewrite /leaf_reduced_candidates /=; '
           'smt().\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'retain-ff',
  'kind': 'finite-counterexample',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount '
             'LeafCandidateMass LeafGrindingCandidates.\n',
  'positive': ': mem (leaf_reduced_candidates [] []) (nseq 16 255)',
  'negative': ': !(mem (leaf_reduced_candidates [] []) (nseq 16 255))',
  'proof': 'have h : mem (leaf_reduced_candidates [] []) (nseq 16 255) by rewrite /leaf_reduced_candidates '
           '/=; smt().\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'two-fixed-slots',
  'kind': 'finite-counterexample',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount '
             'LeafCandidateMass LeafGrindingCandidates.\n',
  'positive': ': size (leaf_reduced_candidates [] [])=2',
  'negative': ': size (leaf_reduced_candidates [] [])=1',
  'proof': 'have h : size (leaf_reduced_candidates [] [])=2 by rewrite leaf_reduced_candidates_size '
           '/leaf_variable_count /=.\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'repeat-malformed',
  'kind': 'finite-counterexample',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount '
             'LeafCandidateMass LeafGrindingCandidates.\n',
  'positive': ': leaf_variable_count [[];[]]=2',
  'negative': ': leaf_variable_count [[];[]]=1',
  'proof': 'have h : leaf_variable_count [[];[]]=2 by rewrite /leaf_variable_count /leaf_variable_query '
           '/leaf_suffix_candidate /=; smt(size_nseq).\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'repeat-fixed',
  'kind': 'finite-counterexample',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount '
             'LeafCandidateMass LeafGrindingCandidates.\n',
  'positive': ': leaf_variable_count [pad (nseq 16 0); pad (nseq 16 255); pad (nseq 16 0)]=0',
  'negative': ': leaf_variable_count [pad (nseq 16 0); pad (nseq 16 255); pad (nseq 16 0)]=3',
  'proof': 'have h : leaf_variable_count [pad (nseq 16 0); pad (nseq 16 255); pad (nseq 16 0)]=0 by have hz '
           ':= padded_leaf_suffix [] (nseq 16 0); have hf := padded_leaf_suffix [] (nseq 16 255);\n'
           '  move: hz hf; rewrite /= !size_nseq /= => hz hf;\n'
           '  rewrite /leaf_variable_count /leaf_variable_query /=; smt().\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'retain-output',
  'kind': 'finite-counterexample',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount '
             'LeafCandidateMass LeafGrindingCandidates.\n',
  'positive': ': mem (leaf_reduced_candidates [] [nseq 16 7]) (nseq 16 7)',
  'negative': ': !mem (leaf_reduced_candidates [] [nseq 16 7]) (nseq 16 7)',
  'proof': 'have h : mem (leaf_reduced_candidates [] [nseq 16 7]) (nseq 16 7) by rewrite '
           '/leaf_reduced_candidates /=; smt().\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'max-u32-counter',
  'kind': 'finite-counterexample',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount '
             'LeafCandidateMass LeafGrindingCandidates.\n',
  'positive': ': !leaf_variable_query ([] ++ be 32 4294967295)',
  'negative': ': leaf_variable_query ([] ++ be 32 4294967295)',
  'proof': 'have h : !leaf_variable_query ([] ++ be 32 4294967295) by apply leaf_counter_candidate_fixed; '
           'smt().\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'counter-width',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen LeafCommitmentHybrid.\n'
             'require import LeafCandidateCount.\n',
  'positive': 'prefix counter : size counter=4 =>\n'
              '  leaf_suffix_candidate (prefix ++ (nseq 28 0 ++ counter)) = nseq 16 0',
  'negative': 'prefix counter : \n  leaf_suffix_candidate (prefix ++ (nseq 28 0 ++ counter)) = nseq 16 0',
  'proof': 'exact (leaf_suffix_zero_counter prefix counter).',
  'diagnostic': '[by]: cannot close goals'},
 {'name': 'counter-range',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr.\n'
             'require import C10RawOracle C10RawGrind C10Counter C10HashDomains C10Representation.\n'
             'require import RawKeygen C10CallerInputBridge LeafCommitmentHybrid LeafCandidateCount.\n'
             'require import LeafGrindingCandidates.\n',
  'positive': 'prefix c : 0<=c<4294967296 =>\n  !leaf_variable_query (prefix ++ be 32 c)',
  'negative': 'prefix c : \n  !leaf_variable_query (prefix ++ be 32 c)',
  'proof': 'exact (leaf_counter_candidate_fixed prefix c).',
  'diagnostic': '[by]: cannot close goals'},
 {'name': 'hmsg-fixed',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr.\n'
             'require import C10RawOracle C10RawGrind C10Counter C10HashDomains C10Representation.\n'
             'require import RawKeygen C10CallerInputBridge LeafCommitmentHybrid LeafCandidateCount.\n'
             'require import LeafGrindingCandidates.\n',
  'positive': 'seed root random message :\n  !leaf_variable_query (hmsg_input seed root random message)',
  'negative': 'seed root random message :\n  leaf_variable_query (hmsg_input seed root random message)',
  'proof': 'exact (leaf_hmsg_candidate_fixed seed root random message).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'fixed-query-only',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen LeafCommitmentHybrid.\n'
             'require import LeafCandidateCount.\n',
  'positive': 'q :\n'
              '  hoare[Independent.hash : !leaf_variable_query x /\\ leaf_variable_count '
              'Independent.queries<=q ==>\n'
              '    leaf_variable_count Independent.queries<=q]',
  'negative': 'q :\n'
              '  hoare[Independent.hash : leaf_variable_count Independent.queries<=q ==>\n'
              '    leaf_variable_count Independent.queries<=q]',
  'proof': 'exact (leaf_variable_hash_fixed q).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'fixed-mass-charge',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr StdOrder.\n'
             'require import C10RawOracle C10Randomizer SecretPrefix PrefixGuess PrefixHybrid RawKeygen '
             'NodeDistribution.\n'
             'require import LeafCommitmentHybrid LeafCommitmentBound LeafCandidateCount.\n'
             'import RealOrder.\n'
             'require import LeafCandidateMass.\n',
  'positive': 'queries outputs :\n'
              '  mu full_digest (fun d => mem (leaf_commitment_candidates queries outputs) (node d)) <=\n'
              '    (leaf_variable_count queries+2+size outputs)%r*(1%r/2%r)^128',
  'negative': 'queries outputs :\n'
              '  mu full_digest (fun d => mem (leaf_commitment_candidates queries outputs) (node d)) <=\n'
              '    (leaf_variable_count queries+1+size outputs)%r*(1%r/2%r)^128',
  'proof': 'exact (leaf_reduced_candidate_mass queries outputs).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'adaptive-budget',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr FMap StdOrder.\n'
             'require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.\n'
             'require import LeafCommitmentHybrid LeafCommitmentBound LeafOpeningBound TargetOracleSplit '
             'TargetPrivateBound.\n'
             'require import LeafCandidateCount LeafCandidateMass.\n'
             'import RealOrder.\n'
             'require import LeafCandidateBound.\n',
  'positive': '(A <: LeafCommitmentContext {-Independent}) q n &m :\n'
              '  0<=q => 0<=n =>\n'
              '  hoare [A(Independent).run : Independent.queries=[] /\\ (glob A)=(glob A){m} ==>\n'
              '    leaf_variable_count Independent.queries<=q /\\ size res<=n] =>\n'
              '  Pr[IndependentLeafGuess(A).run() @ &m : res] <= (q+2+n)%r*(1%r/2%r)^128',
  'negative': '(A <: LeafCommitmentContext {-Independent}) q n &m :\n'
              '  0<=q => 0<=n =>\n'
              '  hoare [A(Independent).run : Independent.queries=[] /\\ (glob A)=(glob A){m} ==>\n'
              '    leaf_variable_count Independent.queries<=q+1 /\\ size res<=n] =>\n'
              '  Pr[IndependentLeafGuess(A).run() @ &m : res] <= (q+2+n)%r*(1%r/2%r)^128',
  'proof': 'move=> hq hn hb; exact (independent_leaf_candidate_at_state A q n &m hq hn hb).',
  'diagnostic': 'this proof-term proves:'},
 {'name': 'hidden-fixed-charge',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr FMap StdOrder.\n'
             'require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.\n'
             'require import LeafCommitmentHybrid LeafCommitmentBound LeafOpeningBound TargetOracleSplit '
             'TargetPrivateBound.\n'
             'require import LeafCandidateCount LeafCandidateMass.\n'
             'import RealOrder.\n'
             'require import LeafCandidateBound.\n',
  'positive': '(A <: LeafCommitmentContext {-LeafCommitmentReal,-LeafCommitmentHybrid,-Shared,-Independent}) '
              'q n &m :\n'
              '  (forall (O <: PrefixOracle {-A}), islossless O.hash => islossless O.derive => islossless '
              'A(O).run) =>\n'
              '  0<=q => 0<=n =>\n'
              '  hoare [A(Independent).run : Independent.queries=[] /\\ (glob A)=(glob A){m} ==>\n'
              '    leaf_variable_count Independent.queries<=q /\\ size res<=n] =>\n'
              '  Pr[RealLeafGuess(A).run() @ &m : res] <= (q+2+n)%r*(1%r/2%r)^128',
  'negative': '(A <: LeafCommitmentContext {-LeafCommitmentReal,-LeafCommitmentHybrid,-Shared,-Independent}) '
              'q n &m :\n'
              '  (forall (O <: PrefixOracle {-A}), islossless O.hash => islossless O.derive => islossless '
              'A(O).run) =>\n'
              '  0<=q => 0<=n =>\n'
              '  hoare [A(Independent).run : Independent.queries=[] /\\ (glob A)=(glob A){m} ==>\n'
              '    leaf_variable_count Independent.queries<=q /\\ size res<=n] =>\n'
              '  Pr[RealLeafGuess(A).run() @ &m : res] <= (q+n)%r*(1%r/2%r)^128',
  'proof': 'move=> ha hq hn hb; exact (adaptive_hidden_leaf_candidate_at_state A q n &m ha hq hn hb).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'final-output-charge',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr FMap StdOrder.\n'
             'require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.\n'
             'require import LeafCommitmentHybrid LeafCommitmentBound LeafOpeningBound TargetOracleSplit '
             'TargetPrivateBound.\n'
             'require import LeafCandidateCount LeafCandidateMass.\n'
             'import RealOrder.\n'
             'require import LeafCandidateBound.\n',
  'positive': '(A <: LeafOpeningContext {-LeafCommitmentReal,-LeafCommitmentHybrid,-Shared,-Independent,\n'
              '    -RealLeafOpening,-RedactedLeafState}) q n &m :\n'
              '  (forall (O <: LeafOpeningOracle {-A}), islossless O.hash => islossless O.derive =>\n'
              '    islossless O.reveal => islossless A(O).run) =>\n'
              '  0<=q => 0<=n =>\n'
              '  hoare [A(RedactedLeafOpening(Independent)).run :\n'
              '    Independent.queries=[] /\\ !RedactedLeafState.revealed /\\ (glob A)=(glob A){m} ==>\n'
              '    leaf_variable_count Independent.queries<=q /\\ size res<=n] =>\n'
              '  Pr[RealUnopenedLeafGuess(A).run() @ &m : res] <= (q+2+n)%r*(1%r/2%r)^128',
  'negative': '(A <: LeafOpeningContext {-LeafCommitmentReal,-LeafCommitmentHybrid,-Shared,-Independent,\n'
              '    -RealLeafOpening,-RedactedLeafState}) q n &m :\n'
              '  (forall (O <: LeafOpeningOracle {-A}), islossless O.hash => islossless O.derive =>\n'
              '    islossless O.reveal => islossless A(O).run) =>\n'
              '  0<=q => 0<=n =>\n'
              '  hoare [A(RedactedLeafOpening(Independent)).run :\n'
              '    Independent.queries=[] /\\ !RedactedLeafState.revealed /\\ (glob A)=(glob A){m} ==>\n'
              '    leaf_variable_count Independent.queries<=q /\\ size res<=n] =>\n'
              '  Pr[RealUnopenedLeafGuess(A).run() @ &m : res] <= (q+2)%r*(1%r/2%r)^128',
  'proof': 'move=> ha hq hn hb; exact (adaptive_unopened_leaf_candidate_at_state A q n &m ha hq hn hb).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'signer-work',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr IntDiv.\n'
             'require import C10RawOracle C10Counter PrefixGuess PrefixHybrid RoleGrindCost KeygenPrefixes.\n'
             'require import RawKeygen RawKeygenCost RawFors RawLayer RawForest RawSigner RoleGrind.\n'
             'require import ForsLeafView LeafForestView TargetOracleSplit TargetByteView '
             'TargetSignerProjection TargetAdapterCost LeafTargetForsCost LeafTargetOracleCost '
             'LeafCandidateCount LeafGrindingCandidates LeafBudgetLayer LeafBudgetShuffle.\n'
             'require import LeafTargetSignerCost.\n',
  'positive': 'q :\n'
              '  hoare[TargetSigning(IdealTarget).sign : leaf_variable_count Independent.queries<=q ==>\n'
              '    leaf_variable_count Independent.queries<= q+364892]',
  'negative': 'q :\n'
              '  hoare[TargetSigning(IdealTarget).sign : leaf_variable_count Independent.queries<=q ==>\n'
              '    leaf_variable_count Independent.queries<= q]',
  'proof': 'exact (leaf_target_signer_sign_candidate_cost q).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'verification-work',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr IntDiv.\n'
             'require import C10RawOracle C10Counter PrefixGuess PrefixHybrid RoleGrindCost KeygenPrefixes.\n'
             'require import RawKeygen RawKeygenCost RawFors RawLayer RawForest RawSigner RoleGrind.\n'
             'require import ForsLeafView LeafForestView TargetOracleSplit TargetByteView '
             'TargetSignerProjection TargetAdapterCost LeafTargetForsCost LeafTargetOracleCost '
             'LeafCandidateCount LeafGrindingCandidates LeafBudgetLayer LeafBudgetShuffle.\n'
             'require import LeafTargetSignerCost.\n',
  'positive': 'q :\n'
              '  hoare[RawSigner(IdealPrefix).verify : leaf_variable_count Independent.queries<=q ==>\n'
              '    leaf_variable_count Independent.queries<= q+771]',
  'negative': 'q :\n'
              '  hoare[RawSigner(IdealPrefix).verify : leaf_variable_count Independent.queries<=q ==>\n'
              '    leaf_variable_count Independent.queries<= q]',
  'proof': 'exact (leaf_target_signer_verify_candidate_cost q).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'raw-query-cap',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr.\n'
             'require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes '
             'KeygenExhaustion.\n'
             'require import RawKeygen RoleGrindCost RawSigner FullSession FullPrefix ByteSession '
             'ExposureLog ClientQueryLog.\n'
             'require import LeafSessionView LeafOpeningBound TargetOracleSplit TargetByteView '
             'TargetSessionOpenings.\n'
             'require import TargetAdapterCost LeafTargetSignerCost LeafBudgetKeygen LeafCandidateCount.\n'
             'require import LeafTargetSessionCost.\n',
  'positive': '(A <: ByteClient '
              '{-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,\n'
              '    -OtherPrivate,-RedactedLeafState,-TargetConfig}) qr qs :\n'
              '  0<=qr => 0<=qs =>\n'
              '  hoare [TargetByteCandidates(A,IdealTarget).run :\n'
              '    FullLimits.raw_cap=qr /\\ FullLimits.sign_cap=qs /\\ Independent.queries=[] ==>\n'
              '    leaf_variable_count Independent.queries<=leaf_candidate_budget qr qs /\\ size res<=12]',
  'negative': '(A <: ByteClient '
              '{-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,\n'
              '    -OtherPrivate,-RedactedLeafState,-TargetConfig}) qr qs :\n'
              '  0<=qr => 0<=qs =>\n'
              '  hoare [TargetByteCandidates(A,IdealTarget).run :\n'
              '    FullLimits.sign_cap=qs /\\ Independent.queries=[] ==>\n'
              '    leaf_variable_count Independent.queries<=leaf_candidate_budget qr qs /\\ size res<=12]',
  'proof': 'move=> hr hs; exact (leaf_target_byte_candidate_cost A qr qs hr hs).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'signing-cap',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr.\n'
             'require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes '
             'KeygenExhaustion.\n'
             'require import RawKeygen RoleGrindCost RawSigner FullSession FullPrefix ByteSession '
             'ExposureLog ClientQueryLog.\n'
             'require import LeafSessionView LeafOpeningBound TargetOracleSplit TargetByteView '
             'TargetSessionOpenings.\n'
             'require import TargetAdapterCost LeafTargetSignerCost LeafBudgetKeygen LeafCandidateCount.\n'
             'require import LeafTargetSessionCost.\n',
  'positive': '(A <: ByteClient '
              '{-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,\n'
              '    -OtherPrivate,-RedactedLeafState,-TargetConfig}) qr qs :\n'
              '  0<=qr => 0<=qs =>\n'
              '  hoare [TargetByteCandidates(A,IdealTarget).run :\n'
              '    FullLimits.raw_cap=qr /\\ FullLimits.sign_cap=qs /\\ Independent.queries=[] ==>\n'
              '    leaf_variable_count Independent.queries<=leaf_candidate_budget qr qs /\\ size res<=12]',
  'negative': '(A <: ByteClient '
              '{-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,\n'
              '    -OtherPrivate,-RedactedLeafState,-TargetConfig}) qr qs :\n'
              '  0<=qr => 0<=qs =>\n'
              '  hoare [TargetByteCandidates(A,IdealTarget).run :\n'
              '    FullLimits.raw_cap=qr /\\ Independent.queries=[] ==>\n'
              '    leaf_variable_count Independent.queries<=leaf_candidate_budget qr qs /\\ size res<=12]',
  'proof': 'move=> hr hs; exact (leaf_target_byte_candidate_cost A qr qs hr hs).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'accepted-output',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr FMap StdOrder.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal RawKeygen ForsPrivateLeaves '
             'FullSession FullPrefix ByteSession.\n'
             'require import KeygenPrefixes KeygenExhaustion ExposureLog ClientQueryLog ClientQueryDriver.\n'
             'require import LeafCommitmentHybrid LeafOpeningBound PrivateTargetSampling.\n'
             'require import TargetOracleSplit TargetTableProjection TargetByteView OriginalTargetEvent '
             'LeafCandidateUnion.\n'
             'require import ForsCoordinateUniverse ActualForsOpening.\n'
             'require import LeafTargetSessionCost OriginalByteTargetBound.\n'
             'import RealOrder.\n'
             'require import LeafForsOpeningBound.\n',
  'positive': '(A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,\n'
              '    '
              '-Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,\n'
              '    '
              '-TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})\n'
              '  qr qs &m :\n'
              '  (forall (O <: ByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless '
              'A(O).run) =>\n'
              '  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>\n'
              '  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res /\\\n'
              '    actual_output_unreturned Independent.rawhistory Independent.secrethistory '
              'FullSession.seed FullSession.root\n'
              '      ExposureLog.entries ClientQueryLog.output] <=\n'
              '    6442450944%r*((leaf_candidate_budget qr qs+2+12)%r*(1%r/2%r)^128)',
  'negative': '(A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,\n'
              '    '
              '-Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,\n'
              '    '
              '-TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})\n'
              '  qr qs &m :\n'
              '  (forall (O <: ByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless '
              'A(O).run) =>\n'
              '  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>\n'
              '  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : actual_output_unreturned '
              'Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root\n'
              '      ExposureLog.entries ClientQueryLog.output] <=\n'
              '    6442450944%r*((leaf_candidate_budget qr qs+2+12)%r*(1%r/2%r)^128)',
  'proof': 'move=> ha hqr hqs hr hs; exact (original_byte_fors_candidate_bound A qr qs &m ha hqr hqs hr hs).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'independent-charge',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr FMap StdOrder.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen '
             'FullPrefix.\n'
             'require import FullSession ByteSession ExposureLog ClientQueryLog.\n'
             'require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates.\n'
             'require import PublicTargetSampling PrivateValueSampling ChainVectorInstall DualDigestSampling '
             'RedactedChainOracle ChainPublicHybrid.\n'
             'require import SelectedChainSampling LateSelectedPreservation EarlyObservedWots '
             'EarlySelectedCharge FreshChainGuess FreshByteBound.\n'
             'require import ObservedValueOpening.\n'
             'require import SelectedWotsBound WotsCoordinateUniverse WotsCoordinateValidity '
             'ActualWotsCoordinate.\n'
             'require import PrefixIdeal ClientQueryDriver OriginalWotsCutBound ActualWotsCut.\n'
             'require import RawSigner RawForest C10HashDomains ExposureComponents ExposurePartition '
             'ByteEncodingCharge EncodingMemoOracle EncodingCollisionState EncodingBirthday.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal RawKeygen ForsPrivateLeaves '
             'FullSession FullPrefix ByteSession.\n'
             'require import KeygenPrefixes KeygenExhaustion ExposureLog ClientQueryLog ClientQueryDriver.\n'
             'require import LeafCommitmentHybrid LeafOpeningBound PrivateTargetSampling.\n'
             'require import TargetOracleSplit TargetTableProjection TargetByteView OriginalTargetEvent '
             'OriginalCandidateUnion.\n'
             'require import ForsCoordinateUniverse ActualForsOpening.\n'
             'require import OriginalWotsCutBound OriginalForsOpeningBound OriginalCoverageBound.\n'
             'require import ProjectedBirthday ProjectedMemoOracle HmsgMemoOracle AcceptedPrefixSampling.\n'
             'require import MemoNodeCollision PublicNodeZero QueryPublicCharges CoveredOutputPool '
             'PoolCoverageBound NumericalByteCases ByteBound PrefixGames.\n'
             'require import StirlingCoverageBound OriginalStirlingCoverage StirlingNumericalBound.\n'
             'require import WotsAcceptanceMass AcceptedEncodingPool AcceptedEncodingCases '
             'AcceptedWotsCollision ByteAcceptedEncodingCharge FullDigestPrefixSampling.\n'
             'require import C10Counter.\n'
             'require import AcceptedEncodingNumericalBound DomainQueryCount DomainSessionCost '
             'DomainNodeCases DomainMemoOracle ByteDomainCollision DomainNumericalBound.\n'
             'require import LeafTargetSessionCost LeafForsOpeningBound.\n'
             'import RealOrder.\n'
             'require import ForsCandidateNumericalBound.\n',
  'positive': '(A <: ByteClient '
              '{-Independent,-Physical,-EncodingMemo,-EncodingSamples,-FullSession,-FullLimits,-KeygenInputs,\n'
              '    '
              '-ExposureLog,-ClientQueryLog,-WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,\n'
              '    '
              '-CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,\n'
              '    '
              '-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,\n'
              '    '
              '-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,\n'
              '    '
              '-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,\n'
              '    -AcceptedSamples,-FullDigestSamples,-DomainMemo,-Hybrid}) qr qs &m :\n'
              '  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless '
              'A(V).run) =>\n'
              '  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>\n'
              '  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res] <= '
              'fors_candidate_independent_euf_charge qr qs',
  'negative': '(A <: ByteClient '
              '{-Independent,-Physical,-EncodingMemo,-EncodingSamples,-FullSession,-FullLimits,-KeygenInputs,\n'
              '    '
              '-ExposureLog,-ClientQueryLog,-WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,\n'
              '    '
              '-CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,\n'
              '    '
              '-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,\n'
              '    '
              '-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,\n'
              '    '
              '-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,\n'
              '    -AcceptedSamples,-FullDigestSamples,-DomainMemo,-Hybrid}) qr qs &m :\n'
              '  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless '
              'A(V).run) =>\n'
              '  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>\n'
              '  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res] <= '
              'fors_candidate_independent_euf_charge qr qs-1%r',
  'proof': 'move=> ha hr hs hqr hqs; exact (original_byte_fors_candidate_euf_bound A qr qs &m ha hr hs hqr '
           'hqs).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'physical-transfer',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr FMap StdOrder.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen '
             'FullPrefix.\n'
             'require import FullSession ByteSession ExposureLog ClientQueryLog.\n'
             'require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates.\n'
             'require import PublicTargetSampling PrivateValueSampling ChainVectorInstall DualDigestSampling '
             'RedactedChainOracle ChainPublicHybrid.\n'
             'require import SelectedChainSampling LateSelectedPreservation EarlyObservedWots '
             'EarlySelectedCharge FreshChainGuess FreshByteBound.\n'
             'require import ObservedValueOpening.\n'
             'require import SelectedWotsBound WotsCoordinateUniverse WotsCoordinateValidity '
             'ActualWotsCoordinate.\n'
             'require import PrefixIdeal ClientQueryDriver OriginalWotsCutBound ActualWotsCut.\n'
             'require import RawSigner RawForest C10HashDomains ExposureComponents ExposurePartition '
             'ByteEncodingCharge EncodingMemoOracle EncodingCollisionState EncodingBirthday.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal RawKeygen ForsPrivateLeaves '
             'FullSession FullPrefix ByteSession.\n'
             'require import KeygenPrefixes KeygenExhaustion ExposureLog ClientQueryLog ClientQueryDriver.\n'
             'require import LeafCommitmentHybrid LeafOpeningBound PrivateTargetSampling.\n'
             'require import TargetOracleSplit TargetTableProjection TargetByteView OriginalTargetEvent '
             'OriginalCandidateUnion.\n'
             'require import ForsCoordinateUniverse ActualForsOpening.\n'
             'require import OriginalWotsCutBound OriginalForsOpeningBound OriginalCoverageBound.\n'
             'require import ProjectedBirthday ProjectedMemoOracle HmsgMemoOracle AcceptedPrefixSampling.\n'
             'require import MemoNodeCollision PublicNodeZero QueryPublicCharges CoveredOutputPool '
             'PoolCoverageBound NumericalByteCases ByteBound PrefixGames.\n'
             'require import StirlingCoverageBound OriginalStirlingCoverage StirlingNumericalBound.\n'
             'require import WotsAcceptanceMass AcceptedEncodingPool AcceptedEncodingCases '
             'AcceptedWotsCollision ByteAcceptedEncodingCharge FullDigestPrefixSampling.\n'
             'require import C10Counter.\n'
             'require import AcceptedEncodingNumericalBound DomainQueryCount DomainSessionCost '
             'DomainNodeCases DomainMemoOracle ByteDomainCollision DomainNumericalBound.\n'
             'require import LeafTargetSessionCost LeafForsOpeningBound.\n'
             'import RealOrder.\n'
             'require import ForsCandidateNumericalBound.\n',
  'positive': '(A <: ByteClient '
              '{-Independent,-Physical,-EncodingMemo,-EncodingSamples,-FullSession,-FullLimits,-KeygenInputs,\n'
              '    '
              '-ExposureLog,-ClientQueryLog,-WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,\n'
              '    '
              '-CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,\n'
              '    '
              '-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,\n'
              '    '
              '-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,\n'
              '    '
              '-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,\n'
              '    -AcceptedSamples,-FullDigestSamples,-DomainMemo,-Hybrid}) qr qs &m :\n'
              '  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless '
              'A(V).run) =>\n'
              '  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>\n'
              '  Pr[RealGame(ByteContext(A)).run() @ &m : res] <= fors_candidate_physical_euf_charge qr qs',
  'negative': '(A <: ByteClient '
              '{-Independent,-Physical,-EncodingMemo,-EncodingSamples,-FullSession,-FullLimits,-KeygenInputs,\n'
              '    '
              '-ExposureLog,-ClientQueryLog,-WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,\n'
              '    '
              '-CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,\n'
              '    '
              '-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,\n'
              '    '
              '-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,\n'
              '    '
              '-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,\n'
              '    -AcceptedSamples,-FullDigestSamples,-DomainMemo,-Hybrid}) qr qs &m :\n'
              '  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless '
              'A(V).run) =>\n'
              '  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>\n'
              '  Pr[RealGame(ByteContext(A)).run() @ &m : res] <= fors_candidate_independent_euf_charge qr '
              'qs',
  'proof': 'move=> ha hr hs hqr hqs; exact (physical_byte_fors_candidate_euf_bound A qr qs &m ha hr hs hqr '
           'hqs).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'charge-comparison',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr FMap StdOrder.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen '
             'FullPrefix.\n'
             'require import FullSession ByteSession ExposureLog ClientQueryLog.\n'
             'require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates.\n'
             'require import PublicTargetSampling PrivateValueSampling ChainVectorInstall DualDigestSampling '
             'RedactedChainOracle ChainPublicHybrid.\n'
             'require import SelectedChainSampling LateSelectedPreservation EarlyObservedWots '
             'EarlySelectedCharge FreshChainGuess FreshByteBound.\n'
             'require import ObservedValueOpening.\n'
             'require import SelectedWotsBound WotsCoordinateUniverse WotsCoordinateValidity '
             'ActualWotsCoordinate.\n'
             'require import PrefixIdeal ClientQueryDriver OriginalWotsCutBound ActualWotsCut.\n'
             'require import RawSigner RawForest C10HashDomains ExposureComponents ExposurePartition '
             'ByteEncodingCharge EncodingMemoOracle EncodingCollisionState EncodingBirthday.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal RawKeygen ForsPrivateLeaves '
             'FullSession FullPrefix ByteSession.\n'
             'require import KeygenPrefixes KeygenExhaustion ExposureLog ClientQueryLog ClientQueryDriver.\n'
             'require import LeafCommitmentHybrid LeafOpeningBound PrivateTargetSampling.\n'
             'require import TargetOracleSplit TargetTableProjection TargetByteView OriginalTargetEvent '
             'OriginalCandidateUnion.\n'
             'require import ForsCoordinateUniverse ActualForsOpening.\n'
             'require import OriginalWotsCutBound OriginalForsOpeningBound OriginalCoverageBound.\n'
             'require import ProjectedBirthday ProjectedMemoOracle HmsgMemoOracle AcceptedPrefixSampling.\n'
             'require import MemoNodeCollision PublicNodeZero QueryPublicCharges CoveredOutputPool '
             'PoolCoverageBound NumericalByteCases ByteBound PrefixGames.\n'
             'require import StirlingCoverageBound OriginalStirlingCoverage StirlingNumericalBound.\n'
             'require import WotsAcceptanceMass AcceptedEncodingPool AcceptedEncodingCases '
             'AcceptedWotsCollision ByteAcceptedEncodingCharge FullDigestPrefixSampling.\n'
             'require import C10Counter.\n'
             'require import AcceptedEncodingNumericalBound DomainQueryCount DomainSessionCost '
             'DomainNodeCases DomainMemoOracle ByteDomainCollision DomainNumericalBound.\n'
             'require import LeafTargetSessionCost LeafForsOpeningBound.\n'
             'import RealOrder.\n'
             'require import ForsCandidateNumericalBound.\n',
  'positive': 'qr qs :\n  fors_candidate_physical_euf_charge qr qs <= domain_node_physical_euf_charge qr qs',
  'negative': 'qr qs :\n'
              '  fors_candidate_physical_euf_charge qr qs <= domain_node_physical_euf_charge qr qs-1%r',
  'proof': 'exact (fors_candidate_physical_charge_tighter qr qs).',
  'diagnostic': 'the given proof-term proves:'}]

def leaf_candidate_outputs(port):
    result = {}
    for item in CHECKS:
        for mode in ('positive', 'reject'):
            claim = item['positive' if mode == 'positive' else 'negative']
            text = item['imports']+'\nlemma checked '+claim+'.\nproof.\n  '+item['proof']+'\nqed.\n'
            text = '\n'.join(line.rstrip() for line in text.splitlines())+'\n'
            stem = 'leaf_candidate_'+item['name'].replace('-', '_')+'_'+mode
            result[port/'scratch'/(stem+'.ec')] = text
    return result

def leaf_candidate_rows():
    rows = []
    for item in CHECKS:
        stem = 'scratch/leaf_candidate_'+item['name'].replace('-', '_')
        rows += [stem+'_positive.ec\tMUST-PASS\t-', stem+'_reject.ec\tMUST-FAIL\t'+item['diagnostic']]
    return rows
