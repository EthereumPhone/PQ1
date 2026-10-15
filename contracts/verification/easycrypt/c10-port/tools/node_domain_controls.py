"""Public-node domain controls. Finite inputs have explicit false paired claims;
the transfer controls test theorem/assumption sensitivity, not lower bounds.
"""

CHECKS = [{'name': 'length-160',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle RawKeygen NodeQueryDomain DomainQueryCount.\n',
  'positive': ': !node_query (nseq 160 0)',
  'negative': ': node_query (nseq 160 0)',
  'proof': 'have h : !node_query (nseq 160 0) by rewrite /node_query size_nseq /=.\n  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'kind-zero-128',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle RawKeygen NodeQueryDomain DomainQueryCount.\n',
  'positive': ': !node_query (nseq 32 0 ++ address 0 0 0 0 0 0 0 ++ pad (nseq 16 0) ++ be 32 0)',
  'negative': ': node_query (nseq 32 0 ++ address 0 0 0 0 0 0 0 ++ pad (nseq 16 0) ++ be 32 0)',
  'proof': 'have h : !node_query (nseq 32 0 ++ address 0 0 0 0 0 0 0 ++ pad (nseq 16 0) ++ be 32 0) by apply '
           'node_query_no_count; rewrite size_nseq /=.\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'pair-kind-2',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle RawKeygen NodeQueryDomain DomainQueryCount.\n',
  'positive': ': node_query (nseq 32 0 ++ address 0 0 2 0 0 0 0 ++ pad (nseq 16 0) ++ pad (nseq 16 0))',
  'negative': ': !node_query (nseq 32 0 ++ address 0 0 2 0 0 0 0 ++ pad (nseq 16 0) ++ pad (nseq 16 0))',
  'proof': 'have h : node_query (nseq 32 0 ++ address 0 0 2 0 0 0 0 ++ pad (nseq 16 0) ++ pad (nseq 16 0)) '
           'by apply node_query_pair => //; smt(size_nseq node_query_merkle_kind).\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'pair-kind-3',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle RawKeygen NodeQueryDomain DomainQueryCount.\n',
  'positive': ': node_query (nseq 32 0 ++ address 0 0 3 0 0 0 0 ++ pad (nseq 16 0) ++ pad (nseq 16 0))',
  'negative': ': !node_query (nseq 32 0 ++ address 0 0 3 0 0 0 0 ++ pad (nseq 16 0) ++ pad (nseq 16 0))',
  'proof': 'have h : node_query (nseq 32 0 ++ address 0 0 3 0 0 0 0 ++ pad (nseq 16 0) ++ pad (nseq 16 0)) '
           'by apply node_query_pair => //; smt(size_nseq node_query_fors_kind).\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'repeat-count',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle RawKeygen NodeQueryDomain DomainQueryCount.\n',
  'positive': ': node_query_count [[];[]]=2',
  'negative': ': node_query_count [[];[]]=1',
  'proof': 'have h : node_query_count [[];[]]=2 by rewrite /node_query_count /node_query /=.\n  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'excluded-count',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle RawKeygen NodeQueryDomain DomainQueryCount.\n',
  'positive': ': node_query_count [nseq 160 0]=0',
  'negative': ': node_query_count [nseq 160 0]=1',
  'proof': 'have h : node_query_count [nseq 160 0]=0 by rewrite /node_query_count /node_query /= size_nseq '
           '/=.\n'
           '  exact h.',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'pair-kind',
  'imports': 'require import AllCore List.\n'
             'require import C10RawOracle C10HashDomains RawKeygen HmsgShapes.\n'
             'require import IndependentWidths RawSignature C10Bytes ClientGuessCandidates '
             'ForsInputSeparation.\n'
             'require import NodeQueryDomain.\n',
  'positive': 'seed layer tree kind kp ci cp ha lhs rhs :\n'
              '  size seed=32 => size lhs=16 => size rhs=16 => be 4 kind <> be 4 0 =>\n'
              '  node_query (seed ++ address layer tree kind kp ci cp ha ++ pad lhs ++ pad rhs)',
  'negative': 'seed layer tree kind kp ci cp ha lhs rhs :\n'
              '  size seed=32 => size lhs=16 => size rhs=16 => \n'
              '  node_query (seed ++ address layer tree kind kp ci cp ha ++ pad lhs ++ pad rhs)',
  'proof': 'exact (node_query_pair seed layer tree kind kp ci cp ha lhs rhs).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'chain-width',
  'imports': 'require import AllCore List.\n'
             'require import C10RawOracle C10HashDomains RawKeygen HmsgShapes.\n'
             'require import IndependentWidths RawSignature C10Bytes ClientGuessCandidates '
             'ForsInputSeparation.\n'
             'require import NodeQueryDomain.\n',
  'positive': 'seed a value :\n'
              '  size seed=32 => size a=32 => size value=16 => node_query (seed ++ a ++ pad value)',
  'negative': 'seed a value :\n  size seed=32 => size a=32 =>  node_query (seed ++ a ++ pad value)',
  'proof': 'exact (node_query_chain seed a value).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'count-seed-width',
  'imports': 'require import AllCore List.\n'
             'require import C10RawOracle C10HashDomains RawKeygen HmsgShapes.\n'
             'require import IndependentWidths RawSignature C10Bytes ClientGuessCandidates '
             'ForsInputSeparation.\n'
             'require import NodeQueryDomain.\n',
  'positive': 'seed layer tree kp message count :\n'
              '  size seed=32 => size message=16 =>\n'
              '  !node_query (seed ++ address layer tree 0 kp 0 0 0 ++ pad message ++ be 32 count)',
  'negative': 'seed layer tree kp message count :\n'
              '   size message=16 =>\n'
              '  !node_query (seed ++ address layer tree 0 kp 0 0 0 ++ pad message ++ be 32 count)',
  'proof': 'exact (node_query_no_count seed layer tree kp message count).',
  'diagnostic': '[by]: cannot close goals'},
 {'name': 'compression-rows',
  'imports': 'require import AllCore List.\n'
             'require import C10RawOracle C10HashDomains RawKeygen HmsgShapes.\n'
             'require import IndependentWidths RawSignature C10Bytes ClientGuessCandidates '
             'ForsInputSeparation.\n'
             'require import NodeQueryDomain.\n',
  'positive': 'seed a rows n :\n'
              '  size seed=32 => size a=32 => rows_width n rows => n=13 \\/ n=43 =>\n'
              '  node_query (seed ++ a ++ flatten (map pad rows))',
  'negative': 'seed a rows n :\n'
              '  size seed=32 => size a=32 => rows_width n rows => \n'
              '  node_query (seed ++ a ++ flatten (map pad rows))',
  'proof': 'exact (node_query_compress seed a rows n).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'wots-domain-collision',
  'imports': 'require import AllCore List FMap RadixEncoding.\n'
             'require import C10RawOracle RawKeygen RawWots RawSignature ClientGuessCandidates.\n'
             'require import LinearChain RawChainTrace WotsReference WotsChainSplit WotsLeafReference '
             'WotsReferenceRoot.\n'
             'require import WotsRecoveryTrace RecoveryCompression RawRecoveryTrace WotsSignatureValue.\n'
             'require import VerifierWotsOpening PublicNodeZero WotsZeroSentinel.\n'
             'require import NodeQueryDomain DomainNodeCollision DomainLinearCollision HmsgShapes.\n'
             'require import DomainWotsOpening.\n',
  'positive': 'h s seed layer tree kp message sigma count root :\n'
              '  size seed=32 =>\n'
              '  wots_root h s seed layer tree kp root => rows_width 43 sigma => 0<=count<4294967296 =>\n'
              '  wots_recovery_trace h seed layer tree kp message sigma count root =>\n'
              '  !domain_node_collision h => !public_node_zero h =>\n'
              '  wots_verifier_opening h s seed layer tree kp message root (sigma,count)',
  'negative': 'h s seed layer tree kp message sigma count root :\n'
              '  size seed=32 =>\n'
              '  wots_root h s seed layer tree kp root => rows_width 43 sigma => 0<=count<4294967296 =>\n'
              '  wots_recovery_trace h seed layer tree kp message sigma count root =>\n'
              '   !public_node_zero h =>\n'
              '  wots_verifier_opening h s seed layer tree kp message root (sigma,count)',
  'proof': 'exact (domain_recovery_trace_opens_reference h s seed layer tree kp message sigma count root).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'table-other',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle RawKeygen NodeQueryDomain DomainNodeCollision.\n'
             'require import DomainNodeTable.\n',
  'positive': 'h nodes x d :\n'
              '  domain_table_recorded h nodes => !node_query x => domain_table_recorded h.[x<-d] nodes',
  'negative': 'h nodes x d :\n  domain_table_recorded h nodes =>  domain_table_recorded h.[x<-d] nodes',
  'proof': 'exact (domain_table_insert_other h nodes x d).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'table-fresh',
  'imports': 'require import AllCore List FMap.\n'
             'require import C10RawOracle RawKeygen NodeQueryDomain DomainNodeCollision.\n'
             'require import DomainNodeTable.\n',
  'positive': 'h nodes x d :\n'
              '  domain_table_recorded h nodes => x\\notin h => node_query x =>\n'
              '  domain_table_recorded h.[x<-d] (node d::nodes)',
  'negative': 'h nodes x d :\n'
              '  domain_table_recorded h nodes =>  node_query x =>\n'
              '  domain_table_recorded h.[x<-d] (node d::nodes)',
  'proof': 'exact (domain_table_insert_node h nodes x d).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'hash-nondomain',
  'imports': 'require import AllCore List Distr.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.\n'
             'require import NodeQueryDomain IndependentWidths.\n'
             'require import DomainQueryCount.\n',
  'positive': 'q :\n'
              '  hoare[Independent.hash : !node_query x /\\ node_query_count Independent.queries<=q ==>\n'
              '    node_query_count Independent.queries<=q]',
  'negative': 'q :\n'
              '  hoare[Independent.hash : node_query_count Independent.queries<=q ==>\n'
              '    node_query_count Independent.queries<=q]',
  'proof': 'exact (domain_hash_nonnode q).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'grinder-width',
  'imports': 'require import AllCore List Distr IntDiv RadixEncoding.\n'
             'require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen '
             'RawWots RawShuffle.\n'
             'require import DomainQueryCount NodeQueryDomain DomainShuffleCost ClientGuessCandidates.\n'
             'require import DomainWotsCost.\n',
  'positive': 'q :\n'
              '  hoare[RawWots(PreparationView(Independent)).count : size seed=32 /\\ size message=16 /\\\n'
              '    node_query_count Independent.queries<=q ==> node_query_count Independent.queries<=q]',
  'negative': 'q :\n'
              '  hoare[RawWots(PreparationView(Independent)).count : size seed=32 /\\ \n'
              '    node_query_count Independent.queries<=q ==> node_query_count Independent.queries<=q]',
  'proof': 'exact (domain_count_cost q).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'signer-budget',
  'imports': 'require import AllCore List Distr.\n'
             'require import C10RawOracle C10RawGrind C10Counter C10Randomizer C10HashDomains.\n'
             'require import PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner RawForest RawLayer '
             'RoleGrind.\n'
             'require import DomainQueryCount NodeQueryDomain DomainForestCost DomainLayerCost '
             'IndependentWidths HmsgShapes.\n'
             'require import DomainSignerCost.\n',
  'positive': 'q :\n'
              '  hoare[RawSigner(Independent).sign : size seed=32 /\\ size root=32 /\\ size message=32 /\\\n'
              '    independent_tables_valid Independent.rawhistory Independent.secrethistory /\\ '
              'node_query_count Independent.queries<=q ==>\n'
              '    node_query_count Independent.queries<=q+364892]',
  'negative': 'q :\n'
              '  hoare[RawSigner(Independent).sign : size seed=32 /\\ size root=32 /\\ size message=32 /\\\n'
              '    independent_tables_valid Independent.rawhistory Independent.secrethistory /\\ '
              'node_query_count Independent.queries<=q ==>\n'
              '    node_query_count Independent.queries<=q]',
  'proof': 'exact (domain_signer_sign_cost q).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'session-budget',
  'imports': 'require import AllCore List Distr.\n'
             'require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes.\n'
             'require import RawKeygen RawKeygenCost KeygenExhaustion RawSigner FullSession FullPrefix '
             'ByteSession.\n'
             'require import IndependentWidths ExposureWidths DomainQueryCount DomainSignerCost.\n'
             'require import DomainSessionCost.\n',
  'positive': '(A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent}) qr qs :\n'
              '  0<=qr => 0<=qs =>\n'
              '  hoare[IndependentGame(ByteContext(A)).run : FullLimits.raw_cap=qr /\\ '
              'FullLimits.sign_cap=qs ==>\n'
              '    node_query_count Independent.queries<=node_public_budget qr qs]',
  'negative': '(A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent}) qr qs :\n'
              '  0<=qr => 0<=qs =>\n'
              '  hoare[IndependentGame(ByteContext(A)).run : FullLimits.sign_cap=qs ==>\n'
              '    node_query_count Independent.queries<=node_public_budget qr qs]',
  'proof': 'move=> hr hs; exact (domain_byte_game_cost A qr qs hr hs).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'adaptive-budget',
  'imports': 'require import AllCore List StdOrder.\n'
             'require import C10RawOracle PrefixGuess PrefixIdeal RawKeygen.\n'
             'require import ProjectedBirthday DomainNodeCollision NodeQueryDomain DomainQueryCount '
             'DomainNodeTable IndependentWidths DomainMemoOracle DomainCollisionGame.\n'
             'import RField RealOrder.\n'
             'require import DomainCollisionBound.\n',
  'positive': '(A <: PrefixContext {-Independent,-DomainMemo,-ProjectedSamples}) q &m :\n'
              '  0<=q =>\n'
              '  hoare [A(Independent).run : Independent.queries=[] /\\ independent_tables_valid '
              'Independent.rawhistory Independent.secrethistory /\\ (glob A)=(glob A){m} ==>\n'
              '    node_query_count Independent.queries<=q] =>\n'
              '  Pr[IndependentDomainCollision(A).run() @ &m : res] <=\n'
              '    (q*(q-1))%r/2%r*(1%r/2%r)^128',
  'negative': '(A <: PrefixContext {-Independent,-DomainMemo,-ProjectedSamples}) q &m :\n'
              '  0<=q =>\n'
              '  hoare [A(Independent).run : Independent.queries=[] /\\ independent_tables_valid '
              'Independent.rawhistory Independent.secrethistory /\\ (glob A)=(glob A){m} ==>\n'
              '    node_query_count Independent.queries<=q+1] =>\n'
              '  Pr[IndependentDomainCollision(A).run() @ &m : res] <=\n'
              '    (q*(q-1))%r/2%r*(1%r/2%r)^128',
  'proof': 'move=> hq hb; exact (domain_node_birthday_at_state A q &m hq hb).',
  'diagnostic': 'this proof-term proves:'},
 {'name': 'byte-event',
  'imports': 'require import AllCore List Distr StdOrder.\n'
             'require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.\n'
             'require import KeygenPrefixes KeygenExhaustion FullSession FullSessionCost FullPrefix '
             'ByteSession ByteBound.\n'
             'require import ProjectedBirthday ProjectedMemoOracle MemoNodeCollision PublicCollisionState.\n'
             'import RealOrder.\n'
             'require import DomainQueryCount DomainNodeCollision DomainMemoOracle DomainCollisionBound '
             'DomainSessionCost IndependentWidths.\n'
             'require import QueryPublicCharges ExposureLog ClientQueryLog ClientQueryDriver.\n'
             'require import ByteDomainCollision.\n',
  'positive': '(A <: ByteClient '
              '{-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-Physical,-DomainMemo,-ProjectedSamples}) '
              'qr qs &m :\n'
              '  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>\n'
              '  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : domain_node_collision '
              'Independent.rawhistory] <=\n'
              '    ((node_public_budget qr qs)*(node_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128',
  'negative': '(A <: ByteClient '
              '{-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-Physical,-DomainMemo,-ProjectedSamples}) '
              'qr qs &m :\n'
              '  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>\n'
              '  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : public_node_collision '
              'Independent.rawhistory] <=\n'
              '    ((node_public_budget qr qs)*(node_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128',
  'proof': 'move=> hr hs hqr hqs; exact (query_byte_domain_collision A qr qs &m hr hs hqr hqs).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'output-partition',
  'imports': 'require import AllCore List Distr FMap.\n'
             'require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes '
             'KeygenExhaustion RawKeygen.\n'
             'require import FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.\n'
             'require import AcceptedActualWotsCut AcceptedWotsCollision.\n'
             'require import MemoNodeCollision PublicNodeZero ByteEncodingCharge ActualExposurePartition '
             'ActualWotsCut ActualForsOpening CoveredOutputPool.\n'
             'require import NodeQueryDomain DomainNodeCollision DomainActualPartition HmsgShapes.\n'
             'require import DomainNodeCases.\n',
  'positive': '(A <: ByteClient '
              '{-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs :\n'
              '  0<=qs =>\n'
              '  hoare[IndependentGame(ClientQueryContext(ByteLift(A))).run : FullLimits.sign_cap=qs ==>\n'
              '    res => domain_node_output_cases Independent.rawhistory Independent.secrethistory\n'
              '      FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output res]',
  'negative': '(A <: ByteClient '
              '{-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs :\n'
              '  0<=qs =>\n'
              '  hoare[IndependentGame(ClientQueryContext(ByteLift(A))).run : FullLimits.sign_cap=qs ==>\n'
              '    domain_node_output_cases Independent.rawhistory Independent.secrethistory\n'
              '      FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output res]',
  'proof': 'move=> hs; exact (query_byte_domain_node_cases A qs hs).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'independent-charge',
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
             'DomainNodeCases DomainMemoOracle ByteDomainCollision.\n'
             'import RealOrder.\n'
             'require import DomainNumericalBound.\n',
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
              'domain_node_independent_euf_charge qr qs',
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
              'domain_node_independent_euf_charge qr qs-1%r',
  'proof': 'move=> ha hr hs hqr hqs; exact (original_byte_domain_node_euf_bound A qr qs &m ha hr hs hqr '
           'hqs).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'physical-transfer',
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
             'DomainNodeCases DomainMemoOracle ByteDomainCollision.\n'
             'import RealOrder.\n'
             'require import DomainNumericalBound.\n',
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
              '  Pr[RealGame(ByteContext(A)).run() @ &m : res] <= domain_node_physical_euf_charge qr qs',
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
              '  Pr[RealGame(ByteContext(A)).run() @ &m : res] <= domain_node_independent_euf_charge qr qs',
  'proof': 'move=> ha hr hs hqr hqs; exact (physical_byte_domain_node_euf_bound A qr qs &m ha hr hs hqr '
           'hqs).',
  'diagnostic': 'the given proof-term proves:'},
 {'name': 'charge-comparison',
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
             'DomainNodeCases DomainMemoOracle ByteDomainCollision.\n'
             'import RealOrder.\n'
             'require import DomainNumericalBound.\n',
  'positive': 'qr qs :\n'
              '  0<=qr => 0<=qs =>\n'
              '  domain_node_physical_euf_charge qr qs<=accepted_encoding_physical_euf_charge qr qs',
  'negative': 'qr qs :\n'
              '  0<=qr => 0<=qs =>\n'
              '  domain_node_physical_euf_charge qr qs<=accepted_encoding_physical_euf_charge qr qs-1%r',
  'proof': 'move=> hr hs; exact (domain_node_physical_charge_tighter qr qs hr hs).',
  'diagnostic': 'the given proof-term proves:'}]

def node_domain_outputs(port):
    result = {}
    for item in CHECKS:
        for mode in ('positive', 'reject'):
            claim = item['positive' if mode == 'positive' else 'negative']
            text = item['imports']+'\nlemma checked '+claim+'.\nproof.\n  '+item['proof']+'\nqed.\n'
            text = '\n'.join(line.rstrip() for line in text.splitlines())+'\n'
            stem = 'node_domain_'+item['name'].replace('-', '_')+'_'+mode
            result[port/'scratch'/(stem+'.ec')] = text
    return result

def node_domain_rows():
    rows = []
    for item in CHECKS:
        stem = 'scratch/node_domain_'+item['name'].replace('-', '_')
        rows += [stem+'_positive.ec\tMUST-PASS\t-', stem+'_reject.ec\tMUST-FAIL\t'+item['diagnostic']]
    return rows
