require import AllCore List C10AcceptedReduction C10HypertreeCorrect C10CubeCorrect C10CubeConstruction GFailCharged XmssmtCC_All.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES WOTS_C_Real WOTS_C_Scheme.
lemma missing_accepted_history ps ad ml pks sigs leaves roots qs :
  cube_good ps ad ml pks sigs leaves roots => size pks = d =>
  qs = cube_records ad ml roots pks sigs =>
  !gfail_of ps qs.
proof. exact (accepted_records ps ad ml pks sigs leaves roots qs). qed.
