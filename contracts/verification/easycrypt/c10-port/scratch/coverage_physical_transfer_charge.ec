require import AllCore List.
require import C10RawOracle RawSigner FullPrefix NumericalByteBound.
lemma physical_charge qr qs :
  physical_euf_charge qr qs = independent_euf_charge qr qs +
    (full_public_budget qr qs)%r*(1%r/2%r)^256.
proof. by rewrite /physical_euf_charge. qed.
