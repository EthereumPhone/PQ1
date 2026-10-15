"""Exact-enumeration paired controls; no failed solver search is credited.

Concrete negatives disagree with checked positive counts/words. Event and
byte-game transfer negatives are proof-sensitivity checks, not lower bounds.
"""

CHECKS = [{'name': 'reverse-labels',
  'imports': 'require import AllCore List StdOrder.\nrequire import ReverseGrowthEncoding.\n',
  'positive': 'reverse_labels [7;3;7]=[0;1;0]',
  'negative': 'reverse_labels [7;3;7]=[1;0;1]',
  'proof': 'have h : reverse_labels [7;3;7]=[0;1;0] by rewrite /reverse_labels /=.\n  exact h.',
  'helper': ''},
 {'name': 'stirling-count',
  'imports': 'require import AllCore List StdOrder.\n'
             'require import RestrictedGrowthWords ReverseGrowthEncoding.\n',
  'positive': 'size (exact_growth_words 12 2)=2047',
  'negative': 'size (exact_growth_words 12 2)=2048',
  'proof': 'have h : size (exact_growth_words 12 2)=2047.\n'
           '  + rewrite exact_growth_words_size 1:/#; exact twelve_two.\n'
           '  exact h.',
  'helper': 'lemma twelve_two : stirling 12 2=2047.\n'
            'proof.\n'
            '  have h0_m : stirling 0 (-1)=0.\n'
            '  + apply stirling_outside; smt().\n'
            '  have h0_0 : stirling 0 (0)=1.\n'
            '  + by rewrite stirling_zero.\n'
            '  have h0_1 : stirling 0 (1)=0.\n'
            '  + apply stirling_outside; smt().\n'
            '  have h0_2 : stirling 0 (2)=0.\n'
            '  + apply stirling_outside; smt().\n'
            '  have h1_m : stirling 1 (-1)=0.\n'
            '  + apply stirling_outside; smt().\n'
            '  have h1_0 : stirling 1 (0)=0.\n'
            '  + have hr:=stirling_recurrence 0 0 _; first smt().\n'
            '    smt().\n'
            '  have h1_1 : stirling 1 (1)=1.\n'
            '  + have hr:=stirling_recurrence 0 1 _; first smt().\n'
            '    smt().\n'
            '  have h1_2 : stirling 1 (2)=0.\n'
            '  + apply stirling_outside; smt().\n'
            '  have h2_m : stirling 2 (-1)=0.\n'
            '  + apply stirling_outside; smt().\n'
            '  have h2_0 : stirling 2 (0)=0.\n'
            '  + have hr:=stirling_recurrence 1 0 _; first smt().\n'
            '    smt().\n'
            '  have h2_1 : stirling 2 (1)=1.\n'
            '  + have hr:=stirling_recurrence 1 1 _; first smt().\n'
            '    smt().\n'
            '  have h2_2 : stirling 2 (2)=1.\n'
            '  + have hr:=stirling_recurrence 1 2 _; first smt().\n'
            '    smt().\n'
            '  have h3_m : stirling 3 (-1)=0.\n'
            '  + apply stirling_outside; smt().\n'
            '  have h3_0 : stirling 3 (0)=0.\n'
            '  + have hr:=stirling_recurrence 2 0 _; first smt().\n'
            '    smt().\n'
            '  have h3_1 : stirling 3 (1)=1.\n'
            '  + have hr:=stirling_recurrence 2 1 _; first smt().\n'
            '    smt().\n'
            '  have h3_2 : stirling 3 (2)=3.\n'
            '  + have hr:=stirling_recurrence 2 2 _; first smt().\n'
            '    smt().\n'
            '  have h4_m : stirling 4 (-1)=0.\n'
            '  + apply stirling_outside; smt().\n'
            '  have h4_0 : stirling 4 (0)=0.\n'
            '  + have hr:=stirling_recurrence 3 0 _; first smt().\n'
            '    smt().\n'
            '  have h4_1 : stirling 4 (1)=1.\n'
            '  + have hr:=stirling_recurrence 3 1 _; first smt().\n'
            '    smt().\n'
            '  have h4_2 : stirling 4 (2)=7.\n'
            '  + have hr:=stirling_recurrence 3 2 _; first smt().\n'
            '    smt().\n'
            '  have h5_m : stirling 5 (-1)=0.\n'
            '  + apply stirling_outside; smt().\n'
            '  have h5_0 : stirling 5 (0)=0.\n'
            '  + have hr:=stirling_recurrence 4 0 _; first smt().\n'
            '    smt().\n'
            '  have h5_1 : stirling 5 (1)=1.\n'
            '  + have hr:=stirling_recurrence 4 1 _; first smt().\n'
            '    smt().\n'
            '  have h5_2 : stirling 5 (2)=15.\n'
            '  + have hr:=stirling_recurrence 4 2 _; first smt().\n'
            '    smt().\n'
            '  have h6_m : stirling 6 (-1)=0.\n'
            '  + apply stirling_outside; smt().\n'
            '  have h6_0 : stirling 6 (0)=0.\n'
            '  + have hr:=stirling_recurrence 5 0 _; first smt().\n'
            '    smt().\n'
            '  have h6_1 : stirling 6 (1)=1.\n'
            '  + have hr:=stirling_recurrence 5 1 _; first smt().\n'
            '    smt().\n'
            '  have h6_2 : stirling 6 (2)=31.\n'
            '  + have hr:=stirling_recurrence 5 2 _; first smt().\n'
            '    smt().\n'
            '  have h7_m : stirling 7 (-1)=0.\n'
            '  + apply stirling_outside; smt().\n'
            '  have h7_0 : stirling 7 (0)=0.\n'
            '  + have hr:=stirling_recurrence 6 0 _; first smt().\n'
            '    smt().\n'
            '  have h7_1 : stirling 7 (1)=1.\n'
            '  + have hr:=stirling_recurrence 6 1 _; first smt().\n'
            '    smt().\n'
            '  have h7_2 : stirling 7 (2)=63.\n'
            '  + have hr:=stirling_recurrence 6 2 _; first smt().\n'
            '    smt().\n'
            '  have h8_m : stirling 8 (-1)=0.\n'
            '  + apply stirling_outside; smt().\n'
            '  have h8_0 : stirling 8 (0)=0.\n'
            '  + have hr:=stirling_recurrence 7 0 _; first smt().\n'
            '    smt().\n'
            '  have h8_1 : stirling 8 (1)=1.\n'
            '  + have hr:=stirling_recurrence 7 1 _; first smt().\n'
            '    smt().\n'
            '  have h8_2 : stirling 8 (2)=127.\n'
            '  + have hr:=stirling_recurrence 7 2 _; first smt().\n'
            '    smt().\n'
            '  have h9_m : stirling 9 (-1)=0.\n'
            '  + apply stirling_outside; smt().\n'
            '  have h9_0 : stirling 9 (0)=0.\n'
            '  + have hr:=stirling_recurrence 8 0 _; first smt().\n'
            '    smt().\n'
            '  have h9_1 : stirling 9 (1)=1.\n'
            '  + have hr:=stirling_recurrence 8 1 _; first smt().\n'
            '    smt().\n'
            '  have h9_2 : stirling 9 (2)=255.\n'
            '  + have hr:=stirling_recurrence 8 2 _; first smt().\n'
            '    smt().\n'
            '  have h10_m : stirling 10 (-1)=0.\n'
            '  + apply stirling_outside; smt().\n'
            '  have h10_0 : stirling 10 (0)=0.\n'
            '  + have hr:=stirling_recurrence 9 0 _; first smt().\n'
            '    smt().\n'
            '  have h10_1 : stirling 10 (1)=1.\n'
            '  + have hr:=stirling_recurrence 9 1 _; first smt().\n'
            '    smt().\n'
            '  have h10_2 : stirling 10 (2)=511.\n'
            '  + have hr:=stirling_recurrence 9 2 _; first smt().\n'
            '    smt().\n'
            '  have h11_m : stirling 11 (-1)=0.\n'
            '  + apply stirling_outside; smt().\n'
            '  have h11_0 : stirling 11 (0)=0.\n'
            '  + have hr:=stirling_recurrence 10 0 _; first smt().\n'
            '    smt().\n'
            '  have h11_1 : stirling 11 (1)=1.\n'
            '  + have hr:=stirling_recurrence 10 1 _; first smt().\n'
            '    smt().\n'
            '  have h11_2 : stirling 11 (2)=1023.\n'
            '  + have hr:=stirling_recurrence 10 2 _; first smt().\n'
            '    smt().\n'
            '  have h12_m : stirling 12 (-1)=0.\n'
            '  + apply stirling_outside; smt().\n'
            '  have h12_0 : stirling 12 (0)=0.\n'
            '  + have hr:=stirling_recurrence 11 0 _; first smt().\n'
            '    smt().\n'
            '  have h12_1 : stirling 12 (1)=1.\n'
            '  + have hr:=stirling_recurrence 11 1 _; first smt().\n'
            '    smt().\n'
            '  have h12_2 : stirling 12 (2)=2047.\n'
            '  + have hr:=stirling_recurrence 11 2 _; first smt().\n'
            '    smt().\n'
            '  exact h12_2.\n'
            'qed.\n'},
 {'name': 'stirling-recurrence',
  'imports': 'require import AllCore List StdOrder.\nrequire import RestrictedGrowthWords.\n',
  'positive': 'stirling 3 2=2*stirling 2 2+stirling 2 1',
  'negative': 'stirling 3 2=stirling 2 2+stirling 2 1',
  'proof': 'have h:=stirling_recurrence 2 2 _; first smt().\n  exact h.',
  'helper': ''},
 {'name': 'distinct-count',
  'imports': 'require import AllCore List StdOrder.\nrequire import DistinctWitnessWords.\n',
  'positive': 'size (distinct_witness_words 4 1 2)=6',
  'negative': 'size (distinct_witness_words 4 1 2)=9',
  'proof': 'have h : size (distinct_witness_words 4 1 2)=6.\n'
           '  + rewrite distinct_witness_words_size 1:/# 1:/# (falling_step 3 1) 1:/# '
           '(falling_step 2 0) 1:/# falling_zero /=.\n'
           '    by [].\n'
           '  exact h.',
  'helper': ''},
 {'name': 'excluded-target',
  'imports': 'require import AllCore List StdOrder.\nrequire import DistinctWitnessWords.\n',
  'positive': '!mem (distinct_witness_words 4 1 1) [1]',
  'negative': 'mem (distinct_witness_words 4 1 1) [1]',
  'proof': 'have h : !mem (distinct_witness_words 4 1 1) [1].\n'
           '  + by rewrite distinct_witness_words_member 1:/# /=.\n'
           '  exact h.',
  'helper': ''},
 {'name': 'insufficient-pool',
  'imports': 'require import AllCore List StdOrder.\nrequire import DistinctWitnessWords.\n',
  'positive': 'distinct_witness_words 3 0 3=[]',
  'negative': 'distinct_witness_words 3 0 3=[[1;2;1]]',
  'proof': 'have h : distinct_witness_words 3 0 3=[].\n'
           '  + apply distinct_witness_words_insufficient; smt().\n'
           '  exact h.',
  'helper': ''},
 {'name': 'empty-selection',
  'imports': 'require import AllCore List StdOrder.\nrequire import DistinctWitnessWords.\n',
  'positive': 'distinct_witness_words 0 0 0=[[]]',
  'negative': 'distinct_witness_words 0 0 0=[]',
  'proof': 'have h : distinct_witness_words 0 0 0=[[]].\n'
           '  + by rewrite /distinct_witness_words distinct_words_zero.\n'
           '  exact h.',
  'helper': ''},
 {'name': 'all-coordinates',
  'imports': 'require import AllCore List StdOrder.\n'
             'require import RestrictedGrowthWords ReverseGrowthEncoding.\n',
  'positive': 'mem (exact_growth_words 12 12) (reverse_labels (range 0 12))',
  'negative': 'mem (exact_growth_words 11 11) (reverse_labels (range 0 12))',
  'proof': 'have h:=reverse_labels_enumerated (range 0 12).\n'
           '  rewrite undup_id 1:range_uniq size_range /= in h.\n'
           '  exact h.',
  'helper': ''},
 {'name': 'event-preservation',
  'imports': 'require import AllCore List StdOrder.\n'
             'require import PoolCoverageEvent StirlingPoolWitness StirlingPoolEvent.\n',
  'positive': 'forall nodes, pool_coverage nodes=stirling_pool_coverage nodes',
  'negative': 'forall nodes, pool_coverage nodes=!stirling_pool_coverage nodes',
  'proof': 'exact pool_coverage_stirling.',
  'helper': ''},
 {'name': 'byte-coverage-transfer',
  'imports': '(* Numerical classical ideal-oracle EUF bound for the initialized byte game.\n'
             '   This is a conservative reduction bound, not a concrete SHA-256 or QROM claim. *)\n'
             'require import AllCore List Distr FMap StdOrder.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion '
             'RawKeygen FullPrefix.\n'
             'require import FullSession ByteSession ExposureLog ClientQueryLog.\n'
             'require import ChainValueView ChainStageSampling CachedChainOracle '
             'ChainByteCandidates.\n'
             'require import PublicTargetSampling PrivateValueSampling ChainVectorInstall '
             'DualDigestSampling RedactedChainOracle ChainPublicHybrid.\n'
             'require import SelectedChainSampling LateSelectedPreservation EarlyObservedWots '
             'EarlySelectedCharge FreshChainGuess FreshByteBound.\n'
             'require import ObservedValueOpening.\n'
             'require import SelectedWotsBound WotsCoordinateUniverse WotsCoordinateValidity '
             'ActualWotsCoordinate.\n'
             'require import PrefixIdeal ClientQueryDriver OriginalWotsCutBound ActualWotsCut.\n'
             'require import RawSigner RawForest C10HashDomains ExposureComponents '
             'ExposurePartition ByteEncodingCharge EncodingMemoOracle EncodingCollisionState '
             'EncodingBirthday.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal RawKeygen '
             'ForsPrivateLeaves FullSession FullPrefix ByteSession.\n'
             'require import KeygenPrefixes KeygenExhaustion ExposureLog ClientQueryLog '
             'ClientQueryDriver.\n'
             'require import LeafCommitmentHybrid LeafOpeningBound PrivateTargetSampling.\n'
             'require import TargetOracleSplit TargetTableProjection TargetByteView '
             'OriginalTargetEvent OriginalCandidateUnion.\n'
             'require import ForsCoordinateUniverse ActualForsOpening.\n'
             'require import OriginalWotsCutBound OriginalForsOpeningBound OriginalCoverageBound.\n'
             'require import ProjectedBirthday ProjectedMemoOracle HmsgMemoOracle '
             'AcceptedPrefixSampling.\n'
             'require import MemoNodeCollision PublicNodeZero QueryPublicCharges CoveredOutputPool '
             'PoolCoverageBound NumericalByteCases ByteBound PrefixGames.\n'
             'require import StirlingCoverageBound OriginalStirlingCoverage '
             'CanonicalNumericalBound NumericalByteBound.\n'
             'import RealOrder.\n'
             '\n'
             'require import StirlingNumericalBound.\n',
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
              '    -AcceptedSamples,-Hybrid}) qr qs &m :\n'
              '  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => '
              'islossless A(V).run) =>\n'
              '  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>\n'
              '  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res] <= '
              'stirling_independent_euf_charge qr qs',
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
              '    -AcceptedSamples,-Hybrid}) qr qs &m :\n'
              '  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => '
              'islossless A(V).run) =>\n'
              '  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>\n'
              '  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res] <= '
              'stirling_independent_euf_charge qr qs-stirling_coverage_charge (qr+qs+1)',
  'proof': 'move=> ha hr hs hqr hqs.\n'
           '  exact (original_byte_stirling_euf_bound A qr qs &m ha hr hs hqr hqs).',
  'helper': '',
  'parameters': True},
 {'name': 'physical-prefix-transfer',
  'imports': '(* Numerical classical ideal-oracle EUF bound for the initialized byte game.\n'
             '   This is a conservative reduction bound, not a concrete SHA-256 or QROM claim. *)\n'
             'require import AllCore List Distr FMap StdOrder.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion '
             'RawKeygen FullPrefix.\n'
             'require import FullSession ByteSession ExposureLog ClientQueryLog.\n'
             'require import ChainValueView ChainStageSampling CachedChainOracle '
             'ChainByteCandidates.\n'
             'require import PublicTargetSampling PrivateValueSampling ChainVectorInstall '
             'DualDigestSampling RedactedChainOracle ChainPublicHybrid.\n'
             'require import SelectedChainSampling LateSelectedPreservation EarlyObservedWots '
             'EarlySelectedCharge FreshChainGuess FreshByteBound.\n'
             'require import ObservedValueOpening.\n'
             'require import SelectedWotsBound WotsCoordinateUniverse WotsCoordinateValidity '
             'ActualWotsCoordinate.\n'
             'require import PrefixIdeal ClientQueryDriver OriginalWotsCutBound ActualWotsCut.\n'
             'require import RawSigner RawForest C10HashDomains ExposureComponents '
             'ExposurePartition ByteEncodingCharge EncodingMemoOracle EncodingCollisionState '
             'EncodingBirthday.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal RawKeygen '
             'ForsPrivateLeaves FullSession FullPrefix ByteSession.\n'
             'require import KeygenPrefixes KeygenExhaustion ExposureLog ClientQueryLog '
             'ClientQueryDriver.\n'
             'require import LeafCommitmentHybrid LeafOpeningBound PrivateTargetSampling.\n'
             'require import TargetOracleSplit TargetTableProjection TargetByteView '
             'OriginalTargetEvent OriginalCandidateUnion.\n'
             'require import ForsCoordinateUniverse ActualForsOpening.\n'
             'require import OriginalWotsCutBound OriginalForsOpeningBound OriginalCoverageBound.\n'
             'require import ProjectedBirthday ProjectedMemoOracle HmsgMemoOracle '
             'AcceptedPrefixSampling.\n'
             'require import MemoNodeCollision PublicNodeZero QueryPublicCharges CoveredOutputPool '
             'PoolCoverageBound NumericalByteCases ByteBound PrefixGames.\n'
             'require import StirlingCoverageBound OriginalStirlingCoverage '
             'CanonicalNumericalBound NumericalByteBound.\n'
             'import RealOrder.\n'
             '\n'
             'require import StirlingNumericalBound.\n',
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
              '    -AcceptedSamples,-Hybrid}) qr qs &m :\n'
              '  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => '
              'islossless A(V).run) =>\n'
              '  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>\n'
              '  Pr[RealGame(ByteContext(A)).run() @ &m : res] <= stirling_physical_euf_charge qr '
              'qs',
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
              '    -AcceptedSamples,-Hybrid}) qr qs &m :\n'
              '  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => '
              'islossless A(V).run) =>\n'
              '  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>\n'
              '  Pr[RealGame(ByteContext(A)).run() @ &m : res] <= stirling_independent_euf_charge '
              'qr qs',
  'proof': 'move=> ha hr hs hqr hqs.\n'
           '  exact (physical_byte_stirling_euf_bound A qr qs &m ha hr hs hqr hqs).',
  'helper': '',
  'parameters': True}]


def stirling_outputs(port):
    outputs = {}
    for item in CHECKS:
        for mode in ('positive', 'reject'):
            claim = item['positive' if mode == 'positive' else 'negative']
            binder = ' ' if item.get('parameters') else ' : '
            source = (item['imports'] + '\n' + item['helper'] + '\nlemma checked' + binder + claim + '.\nproof.\n  ' + item['proof'] + '\nqed.\n')
            stem = 'stirling_' + item['name'].replace('-', '_') + '_' + mode
            outputs[port / 'scratch' / (stem + '.ec')] = source
    return outputs


def stirling_rows():
    rows = []
    for item in CHECKS:
        stem = 'scratch/stirling_' + item['name'].replace('-', '_')
        rows.extend([stem + '_positive.ec\tMUST-PASS\t-',
                     stem + '_reject.ec\tMUST-FAIL\tthe given proof-term proves:'])
    return rows
