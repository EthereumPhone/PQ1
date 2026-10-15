require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Counter C10Randomizer C10HashDomains.
require import PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner RawForest RawLayer RoleGrind.
require import DomainQueryCount NodeQueryDomain DomainForestCost DomainLayerCost IndependentWidths HmsgShapes.
require import DomainSignerCost.

lemma checked q :
  hoare[RawSigner(Independent).sign : size seed=32 /\ size root=32 /\ size message=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ node_query_count Independent.queries<=q ==>
    node_query_count Independent.queries<=q].
proof.
  exact (domain_signer_sign_cost q).
qed.
