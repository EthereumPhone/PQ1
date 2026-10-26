require import AllCore List FSet FMap.
require import C10RawOracle PersistentGrind AcceptedContexts.
require import AddressedOrdinaryInputs AddressedQueryProvenance.
require import AddressedForsException AddressedForsExceptionCount.
require import AddressedMemoCount.
lemma checked h h' s s' seed base queries :
  extends h h' => extends s s' => appended_query_history h base h' queries =>
  ordinary_new_inputs h h' s' seed =>
  nonordinary_count h' s' seed<=nonordinary_count h s seed+
    0.
proof. exact (nonordinary_count_sign_suffix h h' s s' seed base queries). qed.
