"""WOTS fixed/variable candidate controls. Finite pairs have false alternatives;
probability/contract pairs test theorem sensitivity, not falsity of every mutant.
Literal claims do not silently adopt a changed implementation statement.
"""

CHECKS = [{'name': 'retain-zero',
  'kind': 'finite-counterexample',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount '
             'NodeVectorMass ChainCandidateMass.\n',
  'positive': ': mem (chain_candidate_cover []) (nseq 16 0)',
  'negative': ': !(mem (chain_candidate_cover []) (nseq 16 0))',
  'proof': 'have h : mem (chain_candidate_cover []) (nseq 16 0) by rewrite /chain_candidate_cover '
           '/chain_variable_nodes /=; smt().\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'retain-ff',
  'kind': 'finite-counterexample',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount '
             'NodeVectorMass ChainCandidateMass.\n',
  'positive': ': mem (chain_candidate_cover []) (nseq 16 255)',
  'negative': ': !(mem (chain_candidate_cover []) (nseq 16 255))',
  'proof': 'have h : mem (chain_candidate_cover []) (nseq 16 255) by rewrite /chain_candidate_cover '
           '/chain_variable_nodes /=; smt().\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'two-fixed-slots',
  'kind': 'finite-counterexample',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount '
             'NodeVectorMass ChainCandidateMass.\n',
  'positive': ': size (chain_candidate_cover [])=2',
  'negative': ': size (chain_candidate_cover [])=1',
  'proof': 'have h : size (chain_candidate_cover [])=2 by rewrite chain_candidate_cover_size '
           '/chain_variable_nodes /=.\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'repeat-malformed',
  'kind': 'finite-counterexample',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount '
             'NodeVectorMass ChainCandidateMass.\n',
  'positive': ': size (chain_variable_nodes [[];[]])=2',
  'negative': ': size (chain_variable_nodes [[];[]])=1',
  'proof': 'have h : size (chain_variable_nodes [[];[]])=2 by rewrite /chain_variable_nodes /=; '
           'smt(size_nseq).\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'repeat-fixed',
  'kind': 'finite-counterexample',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount '
             'NodeVectorMass ChainCandidateMass.\n',
  'positive': ': size (chain_variable_nodes [nseq 16 0; nseq 16 255; nseq 16 0])=0',
  'negative': ': size (chain_variable_nodes [nseq 16 0; nseq 16 255; nseq 16 0])=3',
  'proof': 'have h : size (chain_variable_nodes [nseq 16 0; nseq 16 255; nseq 16 0])=0 by rewrite '
           '/chain_variable_nodes /=; smt().\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'retain-output',
  'kind': 'finite-counterexample',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount '
             'NodeVectorMass ChainCandidateMass.\n',
  'positive': ': mem (chain_candidate_cover [nseq 16 7]) (nseq 16 7)',
  'negative': ': !mem (chain_candidate_cover [nseq 16 7]) (nseq 16 7)',
  'proof': 'have h : mem (chain_candidate_cover [nseq 16 7]) (nseq 16 7) by apply chain_candidate_cover_mem; '
           'smt().\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'eighth-hidden-value',
  'kind': 'finite-counterexample',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount '
             'NodeVectorMass ChainCandidateMass.\n',
  'positive': ': node_vector_hit [nseq 256 true; nseq 256 true; nseq 256 true; nseq 256 true; nseq 256 true; '
              'nseq 256 true; nseq 256 true; nseq 256 false] [node (nseq 256 false)]',
  'negative': ': !(node_vector_hit [nseq 256 true; nseq 256 true; nseq 256 true; nseq 256 true; nseq 256 '
              'true; nseq 256 true; nseq 256 true; nseq 256 false] [node (nseq 256 false)])',
  'proof': 'have h : node_vector_hit [nseq 256 true; nseq 256 true; nseq 256 true; nseq 256 true; nseq 256 '
           'true; nseq 256 true; nseq 256 true; nseq 256 false] [node (nseq 256 false)] by rewrite '
           '/node_vector_hit /=; smt().\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'fixed-mass-charge',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr DList StdOrder.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount.\n'
             'require import NodeVectorMass VectorGuessBound.\n'
             'import RealOrder.\n'
             'require import ChainCandidateMass.\n',
  'positive': 'candidates :\n'
              '  mu (dlist full_digest 8) (fun ds => node_vector_hit ds candidates) <=\n'
              '    8%r*(size (chain_variable_nodes candidates)+2)%r*(1%r/2%r)^128',
  'negative': 'candidates :\n'
              '  mu (dlist full_digest 8) (fun ds => node_vector_hit ds candidates) <=\n'
              '    8%r*(size (chain_variable_nodes candidates)+1)%r*(1%r/2%r)^128',
  'proof': 'exact (chain_candidate_vector_mass candidates).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'vector-multiplicity',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr DList StdOrder.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount.\n'
             'require import NodeVectorMass VectorGuessBound.\n'
             'import RealOrder.\n'
             'require import ChainCandidateMass.\n',
  'positive': 'candidates :\n'
              '  mu (dlist full_digest 8) (fun ds => node_vector_hit ds candidates) <=\n'
              '    8%r*(size (chain_variable_nodes candidates)+2)%r*(1%r/2%r)^128',
  'negative': 'candidates :\n'
              '  mu (dlist full_digest 8) (fun ds => node_vector_hit ds candidates) <=\n'
              '    7%r*(size (chain_variable_nodes candidates)+2)%r*(1%r/2%r)^128',
  'proof': 'exact (chain_candidate_vector_mass candidates).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'adaptive-budget',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr DList StdOrder.\n'
             'require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount.\n'
             'require import NodeVectorMass VectorGuessBound.\n'
             'import RealOrder.\n'
             'require import ChainCandidateMass.\n',
  'positive': '(P <: CandidateProducer) k &m :\n'
              '  0<=k =>\n'
              '  hoare [P.run : (glob P)=(glob P){m} ==> size (chain_variable_nodes res)<=k] =>\n'
              '  Pr[IndependentVectorGuess(P).run() @ &m : res] <= 8%r*(k+2)%r*(1%r/2%r)^128',
  'negative': '(P <: CandidateProducer) k &m :\n'
              '  0<=k =>\n'
              '  hoare [P.run : (glob P)=(glob P){m} ==> size (chain_variable_nodes res)<=k+1] =>\n'
              '  Pr[IndependentVectorGuess(P).run() @ &m : res] <= 8%r*(k+2)%r*(1%r/2%r)^128',
  'proof': 'exact (independent_vector_candidate_bound P k &m).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'cut-range',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr DList FMap StdOrder.\n'
             'require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.\n'
             'require import ChainValueView ChainStageSampling CachedChainOracle DualDigestSampling.\n'
             'require import RedactedChainOracle ChainPublicHybrid ChainHybridContext.\n'
             'require import ChainVectorInstall VisibleChainInstallation ChainVisibleGuess NodeVectorMass '
             'VectorGuessBound.\n'
             'import RealOrder.\n'
             'require import ProgrammedChainBound ChainCandidateMass.\n'
             'require import ChainCandidateBound.\n',
  'positive': '(A <: ChainContext {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-ChainRedaction,\n'
              '    '
              '-ChainVectorInstall,-CachedChain,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain})\n'
              '  k &m :\n'
              '  (forall (O <: ChainOracle {-A}), islossless O.hash => islossless O.derive =>\n'
              '    islossless O.value => islossless A(O).run) =>\n'
              '  0<=ChainCut.cut{m}<7 => 0<=k =>\n'
              '  hoare [VisibleChainCandidates(A).run :\n'
              '    (glob VisibleChainCandidates(A))=(glob VisibleChainCandidates(A)){m} ==> size '
              '(chain_variable_nodes res)<=k] =>\n'
              '  Pr[ProgrammedUnopenedChainGuess(A).run() @ &m : res] <= 8%r*(k+2)%r*(1%r/2%r)^128',
  'negative': '(A <: ChainContext {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-ChainRedaction,\n'
              '    '
              '-ChainVectorInstall,-CachedChain,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain})\n'
              '  k &m :\n'
              '  (forall (O <: ChainOracle {-A}), islossless O.hash => islossless O.derive =>\n'
              '    islossless O.value => islossless A(O).run) =>\n'
              '   0<=k =>\n'
              '  hoare [VisibleChainCandidates(A).run :\n'
              '    (glob VisibleChainCandidates(A))=(glob VisibleChainCandidates(A)){m} ==> size '
              '(chain_variable_nodes res)<=k] =>\n'
              '  Pr[ProgrammedUnopenedChainGuess(A).run() @ &m : res] <= 8%r*(k+2)%r*(1%r/2%r)^128',
  'proof': 'exact (programmed_unopened_chain_candidate_bound A k &m).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'cached-value-work',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr IntDiv RadixEncoding.\n'
             'require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.\n'
             'require import RoleGrind RoleGrindCost RawShuffle RawWots RedactedChainOracle ChainValueView.\n'
             'require import LeafCandidateCount LeafGrindingCandidates.\n'
             'require import ChainVariableBasicCost.\n',
  'positive': 'q :\n'
              '  hoare[RedactedCachedChain.value :\n'
              '    leaf_variable_count Independent.queries<=q /\\ 0<=stop<=7 ==>\n'
              '    leaf_variable_count Independent.queries<=q+7]',
  'negative': 'q :\n'
              '  hoare[RedactedCachedChain.value :\n'
              '    leaf_variable_count Independent.queries<=q /\\ 0<=stop<=7 ==>\n'
              '    leaf_variable_count Independent.queries<=q]',
  'proof': 'exact (chain_variable_cached_value_cost q).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'signer-work',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr.\n'
             'require import C10RawOracle C10RawGrind C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.\n'
             'require import RawKeygen PhysicalKeygenCost RoleGrind RoleGrindCost.\n'
             'require import RawForest RawForestCost RawLayer RawLayerCost RawSigner.\n'
             'require import ChainValueView ChainLayerView ChainSignerView RedactedChainOracle '
             'ChainVariableBasicCost ChainVariableWotsCost ChainVariableMerkleCost ChainVariableForestCost '
             'ChainVariableLayerCost.\n'
             'require import LeafCandidateCount LeafGrindingCandidates.\n'
             'require import ChainVariableSignerCost.\n',
  'positive': 'q :\n'
              '  hoare[ChainSigner(RedactedCachedChain).sign : leaf_variable_count Independent.queries<=q '
              '==>\n'
              '    leaf_variable_count Independent.queries <= q+364892]',
  'negative': 'q :\n'
              '  hoare[ChainSigner(RedactedCachedChain).sign : leaf_variable_count Independent.queries<=q '
              '==>\n'
              '    leaf_variable_count Independent.queries <= q]',
  'proof': 'exact (chain_variable_signer_sign_public_cost q).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'verification-work',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr.\n'
             'require import C10RawOracle C10RawGrind C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.\n'
             'require import RawKeygen PhysicalKeygenCost RoleGrind RoleGrindCost.\n'
             'require import RawForest RawForestCost RawLayer RawLayerCost RawSigner.\n'
             'require import ChainValueView ChainLayerView ChainSignerView RedactedChainOracle '
             'ChainVariableBasicCost ChainVariableWotsCost ChainVariableMerkleCost ChainVariableForestCost '
             'ChainVariableLayerCost.\n'
             'require import LeafCandidateCount LeafGrindingCandidates.\n'
             'require import ChainVariableSignerCost.\n',
  'positive': 'q :\n'
              '  hoare[RawSigner(ChainPrefix(RedactedCachedChain)).verify : leaf_variable_count '
              'Independent.queries<=q ==>\n'
              '    leaf_variable_count Independent.queries <= q+771]',
  'negative': 'q :\n'
              '  hoare[RawSigner(ChainPrefix(RedactedCachedChain)).verify : leaf_variable_count '
              'Independent.queries<=q ==>\n'
              '    leaf_variable_count Independent.queries <= q]',
  'proof': 'exact (chain_variable_signer_verify_public_cost q).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'raw-query-cap',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List.\n'
             'require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes '
             'KeygenExhaustion RoleGrindCost.\n'
             'require import FullSession ByteSession ExposureLog ClientQueryLog.\n'
             'require import ChainValueView ChainSessionView RedactedChainOracle ChainVariableKeygenCost '
             'ChainVariableSignerCost.\n'
             'require import LeafCandidateCount LeafGrindingCandidates.\n'
             'require import ChainVariableSessionCost.\n',
  'positive': '(A <: FullClient '
              '{-FullSession,-Independent,-ExposureLog,-ClientQueryLog,-FullLimits,-KeygenInputs}) qr qs :\n'
              '  0<=qr => 0<=qs =>\n'
              '  hoare[ChainQueryContext(A,RedactedCachedChain).run :\n'
              '    FullLimits.raw_cap=qr /\\ FullLimits.sign_cap=qs /\\ leaf_variable_count '
              'Independent.queries<=0 ==>\n'
              '    leaf_variable_count Independent.queries<=155135+qr+qs*(364892)+771]',
  'negative': '(A <: FullClient '
              '{-FullSession,-Independent,-ExposureLog,-ClientQueryLog,-FullLimits,-KeygenInputs}) qr qs :\n'
              '  0<=qr => 0<=qs =>\n'
              '  hoare[ChainQueryContext(A,RedactedCachedChain).run :\n'
              '    FullLimits.sign_cap=qs /\\ leaf_variable_count Independent.queries<=0 ==>\n'
              '    leaf_variable_count Independent.queries<=155135+qr+qs*(364892)+771]',
  'proof': 'move=> hr hs; exact (chain_variable_context_cost A qr qs hr hs).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'signing-cap',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List.\n'
             'require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes '
             'KeygenExhaustion RoleGrindCost.\n'
             'require import FullSession ByteSession ExposureLog ClientQueryLog.\n'
             'require import ChainValueView ChainSessionView RedactedChainOracle ChainVariableKeygenCost '
             'ChainVariableSignerCost.\n'
             'require import LeafCandidateCount LeafGrindingCandidates.\n'
             'require import ChainVariableSessionCost.\n',
  'positive': '(A <: FullClient '
              '{-FullSession,-Independent,-ExposureLog,-ClientQueryLog,-FullLimits,-KeygenInputs}) qr qs :\n'
              '  0<=qr => 0<=qs =>\n'
              '  hoare[ChainQueryContext(A,RedactedCachedChain).run :\n'
              '    FullLimits.raw_cap=qr /\\ FullLimits.sign_cap=qs /\\ leaf_variable_count '
              'Independent.queries<=0 ==>\n'
              '    leaf_variable_count Independent.queries<=155135+qr+qs*(364892)+771]',
  'negative': '(A <: FullClient '
              '{-FullSession,-Independent,-ExposureLog,-ClientQueryLog,-FullLimits,-KeygenInputs}) qr qs :\n'
              '  0<=qr => 0<=qs =>\n'
              '  hoare[ChainQueryContext(A,RedactedCachedChain).run :\n'
              '    FullLimits.raw_cap=qr /\\ leaf_variable_count Independent.queries<=0 ==>\n'
              '    leaf_variable_count Independent.queries<=155135+qr+qs*(364892)+771]',
  'proof': 'move=> hr hs; exact (chain_variable_context_cost A qr qs hr hs).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'output-slots',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr DList.\n'
             'require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid KeygenPrefixes '
             'KeygenExhaustion FullPrefix.\n'
             'require import FullSession ByteSession ExposureLog ClientQueryLog.\n'
             'require import ChainValueView ChainSessionView ChainByteCandidates RedactedChainOracle '
             'ChainVariableSessionCost.\n'
             'require import RawKeygen LeafCandidateCount ChainCandidateMass.\n'
             'require import ChainTableInstallation VisibleChainInstallation ChainVisibleGuess.\n'
             'require import VisibleChainCandidateBudget.\n',
  'positive': '(A <: ByteClient '
              '{-FullSession,-Independent,-ExposureLog,-ClientQueryLog,-FullLimits,-KeygenInputs}) qr qs :\n'
              '  0<=qr => 0<=qs =>\n'
              '  hoare[VisibleChainCandidates(ChainByteCandidates(A)).run :\n'
              '    FullLimits.raw_cap=qr /\\ FullLimits.sign_cap=qs ==>\n'
              '    size (chain_variable_nodes res)<=chain_candidate_budget qr qs+86]',
  'negative': '(A <: ByteClient '
              '{-FullSession,-Independent,-ExposureLog,-ClientQueryLog,-FullLimits,-KeygenInputs}) qr qs :\n'
              '  0<=qr => 0<=qs =>\n'
              '  hoare[VisibleChainCandidates(ChainByteCandidates(A)).run :\n'
              '    FullLimits.raw_cap=qr /\\ FullLimits.sign_cap=qs ==>\n'
              '    size (chain_variable_nodes res)<=chain_candidate_budget qr qs+85]',
  'proof': 'move=> hr hs; exact (visible_chain_candidate_budget A qr qs hr hs).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'seed-binding',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr StdOrder.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen '
             'FullPrefix.\n'
             'require import FullSession ByteSession ExposureLog ClientQueryLog.\n'
             'require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates.\n'
             'require import PublicTargetSampling PrivateValueSampling ChainVectorInstall DualDigestSampling '
             'RedactedChainOracle ChainPublicHybrid.\n'
             'require import SelectedChainSampling LateSelectedPreservation EarlyObservedWots '
             'EarlySelectedCharge FreshChainGuess FreshCandidateByteBound.\n'
             'require import ObservedValueOpening.\n'
             'require import ChainVariableSessionCost ChainCandidateMass ChainCandidateBound '
             'OriginalWotsCoordinateBound.\n'
             'import RealOrder.\n'
             'require import SelectedWotsCandidateBound.\n',
  'positive': '(A <: ByteClient '
              '{-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,\n'
              '    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,\n'
              '    '
              '-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,\n'
              '    '
              '-ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,\n'
              '    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) &m :\n'
              '  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless '
              'A(V).run) =>\n'
              '  ChainStage.seed{m}=pad(node KeygenInputs.public_seed{m}) =>\n'
              '  valid_chain_address ChainStage.layer{m} ChainStage.tree{m} ChainStage.kp{m} '
              'ChainStage.index{m} =>\n'
              '  0<=ChainCut.cut{m}<7 => 0<=FullLimits.raw_cap{m} => 0<=FullLimits.sign_cap{m} =>\n'
              '  Pr[SelectedWotsGame(A).run() @ &m : res] <=\n'
              '    8%r*(chain_candidate_budget FullLimits.raw_cap{m} '
              'FullLimits.sign_cap{m}+86+2)%r*(1%r/2%r)^128',
  'negative': '(A <: ByteClient '
              '{-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,\n'
              '    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,\n'
              '    '
              '-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,\n'
              '    '
              '-ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,\n'
              '    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) &m :\n'
              '  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless '
              'A(V).run) =>\n'
              '  \n'
              '  valid_chain_address ChainStage.layer{m} ChainStage.tree{m} ChainStage.kp{m} '
              'ChainStage.index{m} =>\n'
              '  0<=ChainCut.cut{m}<7 => 0<=FullLimits.raw_cap{m} => 0<=FullLimits.sign_cap{m} =>\n'
              '  Pr[SelectedWotsGame(A).run() @ &m : res] <=\n'
              '    8%r*(chain_candidate_budget FullLimits.raw_cap{m} '
              'FullLimits.sign_cap{m}+86+2)%r*(1%r/2%r)^128',
  'proof': 'exact (selected_wots_candidate_bound A &m).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'coordinate-universe',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr StdOrder.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen '
             'FullPrefix.\n'
             'require import FullSession ByteSession ExposureLog ClientQueryLog.\n'
             'require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates.\n'
             'require import PublicTargetSampling PrivateValueSampling ChainVectorInstall DualDigestSampling '
             'RedactedChainOracle ChainPublicHybrid.\n'
             'require import SelectedChainSampling LateSelectedPreservation EarlyObservedWots '
             'EarlySelectedCharge FreshChainGuess FreshCandidateByteBound.\n'
             'require import ObservedValueOpening.\n'
             'require import SelectedWotsCandidateBound WotsCoordinateUniverse WotsCoordinateValidity '
             'ActualWotsCoordinate.\n'
             'require import WotsCandidateCoordinateBound.\n'
             'require import ChainVariableSessionCost ChainCandidateMass ChainCandidateBound '
             'OriginalWotsCoordinateBound.\n'
             'import RealOrder.\n'
             'require import WotsCandidateUnion.\n',
  'positive': '(A <: ByteClient '
              '{-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,\n'
              '    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,\n'
              '    '
              '-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,\n'
              '    '
              '-ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,\n'
              '    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs &m :\n'
              '  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless '
              'A(V).run) =>\n'
              '  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>\n'
              '  Pr[OriginalWotsCandidateGame(A).run() @ &m : exists c, mem wots_coordinates c /\\\n'
              '    selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed '
              'FullSession.root\n'
              '      ExposureLog.entries res c] <=\n'
              '    632475648%r*((chain_candidate_budget qr qs+86+2)%r*(1%r/2%r)^128)',
  'negative': '(A <: ByteClient '
              '{-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,\n'
              '    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,\n'
              '    '
              '-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,\n'
              '    '
              '-ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,\n'
              '    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs &m :\n'
              '  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless '
              'A(V).run) =>\n'
              '  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>\n'
              '  Pr[OriginalWotsCandidateGame(A).run() @ &m : exists c, mem wots_coordinates c /\\\n'
              '    selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed '
              'FullSession.root\n'
              '      ExposureLog.entries res c] <=\n'
              '    632475647%r*((chain_candidate_budget qr qs+86+2)%r*(1%r/2%r)^128)',
  'proof': 'move=> ha hr hs hqr hqs; exact (original_wots_candidate_universe_bound A qr qs &m ha hr hs hqr '
           'hqs).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'accepted-output',
  'kind': 'theorem-sensitivity',
  'imports': 'require import AllCore List Distr StdOrder.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen '
             'FullPrefix.\n'
             'require import FullSession ByteSession ExposureLog ClientQueryLog.\n'
             'require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates.\n'
             'require import PublicTargetSampling PrivateValueSampling ChainVectorInstall DualDigestSampling '
             'RedactedChainOracle ChainPublicHybrid.\n'
             'require import SelectedChainSampling LateSelectedPreservation EarlyObservedWots '
             'EarlySelectedCharge FreshChainGuess FreshCandidateByteBound.\n'
             'require import ObservedValueOpening.\n'
             'require import SelectedWotsCandidateBound WotsCoordinateUniverse WotsCoordinateValidity '
             'ActualWotsCoordinate.\n'
             'require import PrefixIdeal ClientQueryDriver WotsCandidateUnion WotsCandidateCoordinateBound '
             'ActualWotsCut.\n'
             'require import ChainVariableSessionCost ChainCandidateMass ChainCandidateBound '
             'OriginalWotsCoordinateBound.\n'
             'import RealOrder.\n'
             'require import WotsCandidateCutBound.\n',
  'positive': '(A <: ByteClient '
              '{-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,\n'
              '    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,\n'
              '    '
              '-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,\n'
              '    '
              '-ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,\n'
              '    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs &m :\n'
              '  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless '
              'A(V).run) =>\n'
              '  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>\n'
              '  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res /\\\n'
              '    (actual_top_cut Independent.rawhistory Independent.secrethistory FullSession.seed '
              'FullSession.root\n'
              '      ExposureLog.entries ClientQueryLog.output \\/\n'
              '     actual_bottom_cut Independent.rawhistory Independent.secrethistory FullSession.seed '
              'FullSession.root\n'
              '      ExposureLog.entries ClientQueryLog.output)] <=\n'
              '    632475648%r*((chain_candidate_budget qr qs+86+2)%r*(1%r/2%r)^128)',
  'negative': '(A <: ByteClient '
              '{-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,\n'
              '    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,\n'
              '    '
              '-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,\n'
              '    '
              '-ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,\n'
              '    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs &m :\n'
              '  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless '
              'A(V).run) =>\n'
              '  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>\n'
              '  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : (actual_top_cut '
              'Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root\n'
              '      ExposureLog.entries ClientQueryLog.output \\/\n'
              '     actual_bottom_cut Independent.rawhistory Independent.secrethistory FullSession.seed '
              'FullSession.root\n'
              '      ExposureLog.entries ClientQueryLog.output)] <=\n'
              '    632475648%r*((chain_candidate_budget qr qs+86+2)%r*(1%r/2%r)^128)',
  'proof': 'move=> ha hr hs hqr hqs; exact (original_byte_wots_candidate_cut_bound A qr qs &m ha hr hs hqr '
           'hqs).',
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
             'require import ForsCandidateNumericalBound ChainVariableSessionCost WotsCandidateCutBound.\n'
             'import RealOrder.\n'
             'require import WotsCandidateNumericalBound.\n',
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
              'wots_candidate_independent_euf_charge qr qs',
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
              'wots_candidate_independent_euf_charge qr qs-1%r',
  'proof': 'move=> ha hr hs hqr hqs; exact (original_byte_wots_candidate_euf_bound A qr qs &m ha hr hs hqr '
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
             'require import ForsCandidateNumericalBound ChainVariableSessionCost WotsCandidateCutBound.\n'
             'import RealOrder.\n'
             'require import WotsCandidateNumericalBound.\n',
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
              '  Pr[RealGame(ByteContext(A)).run() @ &m : res] <= wots_candidate_physical_euf_charge qr qs',
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
              '  Pr[RealGame(ByteContext(A)).run() @ &m : res] <= wots_candidate_independent_euf_charge qr '
              'qs',
  'proof': 'move=> ha hr hs hqr hqs; exact (physical_byte_wots_candidate_euf_bound A qr qs &m ha hr hs hqr '
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
             'require import ForsCandidateNumericalBound ChainVariableSessionCost WotsCandidateCutBound.\n'
             'import RealOrder.\n'
             'require import WotsCandidateNumericalBound.\n',
  'positive': 'qr qs :\n'
              '  wots_candidate_physical_euf_charge qr qs <= fors_candidate_physical_euf_charge qr qs',
  'negative': 'qr qs :\n'
              '  wots_candidate_physical_euf_charge qr qs <= fors_candidate_physical_euf_charge qr qs-1%r',
  'proof': 'exact (wots_candidate_physical_charge_tighter qr qs).',
  'diagnostic': 'the given proof-term proves:'}]

def chain_candidate_outputs(port):
    result = {}
    for item in CHECKS:
        for mode in ('positive', 'reject'):
            claim = item['positive' if mode == 'positive' else 'negative']
            text = item['imports']+'\nlemma checked '+claim+'.\nproof.\n  '+item['proof']+'\nqed.\n'
            text = '\n'.join(line.rstrip() for line in text.splitlines())+'\n'
            stem = 'chain_candidate_'+item['name'].replace('-', '_')+'_'+mode
            result[port/'scratch'/(stem+'.ec')] = text
    return result

def chain_candidate_rows():
    rows = []
    for item in CHECKS:
        stem = 'scratch/chain_candidate_'+item['name'].replace('-', '_')
        rows += [stem+'_positive.ec\tMUST-PASS\t-', stem+'_reject.ec\tMUST-FAIL\t'+item['diagnostic']]
    return rows
