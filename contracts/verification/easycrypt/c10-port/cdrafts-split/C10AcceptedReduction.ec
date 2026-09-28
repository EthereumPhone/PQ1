(* Accepted public transcripts imply no grind failure in the actual reduced leaf game. *)
require import AllCore List Distr C10HypertreeCorrect C10CubeCorrect C10CubeConstruction C10ReductionChoose C10ReductionForge GFailCharged XmssmtCC_All.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES WOTS_C_Real WOTS_C_Scheme.

section.
declare module A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF
  {-Observe,-R_MEUFGCMAWOTSC_EUFNAGCMA_C,-O_MEUFGCMA_WOTSC_Default,-FC.O_THFC_Default}.
module R = R_MEUFGCMAWOTSC_EUFNAGCMA_C(Observe(A),O_MEUFGCMA_WOTSC_Default,FC.O_THFC_Default).

lemma observed_choose_build ps0 :
  hoare[R.choose :
    O_MEUFGCMA_WOTSC_Default.ps = ps0 /\ FC.O_THFC_Default.pp = ps0 /\
    O_MEUFGCMA_WOTSC_Default.qs = [] ==>
    R.ad = adz /\ O_MEUFGCMA_WOTSC_Default.ps = ps0 /\ FC.O_THFC_Default.pp = ps0 /\
    cube_good ps0 R.ad R.ml R.pkWOTStd R.sigWOTStd R.leavestd R.rootstd /\
    size R.pkWOTStd = d /\ R.ml = Observe.messages /\
    O_MEUFGCMA_WOTSC_Default.qs = cube_records R.ad R.ml R.rootstd R.pkWOTStd R.sigWOTStd].
proof.
  conseq (choose_build (Observe(A)) ps0) (choose_messages A); smt().
qed.

lemma accepted_records ps ad ml pks sigs leaves roots qs :
  cube_good ps ad ml pks sigs leaves roots => size pks = d =>
  qs = cube_records ad ml roots pks sigs =>
  good_transcript (root_at roots (d-1) 0,ps,ad) ml
    (mkseq (cube_path ps ad sigs leaves) l) => !gfail_of ps qs.
proof.
  move=> hc hd hq hg.
  apply (accepted_cube_no_failure ps ad ml pks sigs leaves roots qs).
  + exact (completed_cube_consistent ps ad ml pks sigs leaves roots hc hd).
  + exact hg.
  move=> q hmem; apply (completed_cube_records ps ad ml pks sigs leaves roots q hc hd).
  by rewrite -hq.
qed.

lemma forge_accepted_no_failure :
  hoare[R.forge :
    ps = O_MEUFGCMA_WOTSC_Default.ps /\
    cube_good ps R.ad R.ml R.pkWOTStd R.sigWOTStd R.leavestd R.rootstd /\
    size R.pkWOTStd = d /\ R.ml = Observe.messages /\
    O_MEUFGCMA_WOTSC_Default.qs = cube_records R.ad R.ml R.rootstd R.pkWOTStd R.sigWOTStd ==>
    good_transcript Observe.public Observe.messages Observe.signatures =>
      !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
proof.
  proc*; exists* ps, R.ad, R.ml, R.sigWOTStd, R.leavestd, R.rootstd;
    elim* => ps0 ad0 ml0 sigs0 leaves0 roots0.
  call (forge_shape A ps0 ad0 ml0 sigs0 leaves0 roots0).
  auto; smt(accepted_records).
qed.

lemma reduced_game_accepted_no_failure :
  hoare[M_EUF_GCMA_WOTSC_NPRF(R_MEUFGCMAWOTSC_EUFNAGCMA_C(Observe(A)),
    O_MEUFGCMA_WOTSC_Default,FC.O_THFC_Default).main : true ==>
    good_transcript Observe.public Observe.messages Observe.signatures =>
      !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
proof.
  proc; seq 1 : true; first by auto.
  exists* ps; elim* => ps0.
  seq 3 : (ps = ps0 /\
    O_MEUFGCMA_WOTSC_Default.ps = ps0 /\
    cube_good ps0 R.ad R.ml R.pkWOTStd R.sigWOTStd R.leavestd R.rootstd /\
    size R.pkWOTStd = d /\ R.ml = Observe.messages /\
    O_MEUFGCMA_WOTSC_Default.qs = cube_records R.ad R.ml R.rootstd R.pkWOTStd R.sigWOTStd).
  + call (observed_choose_build ps0); inline *; auto; smt().
  inline O_MEUFGCMA_WOTSC_Default.get O_MEUFGCMA_WOTSC_Default.nr_queries
    O_MEUFGCMA_WOTSC_Default.dist_addresses O_MEUFGCMA_WOTSC_Default.get_addresses
    FC.O_THFC_Default.get_tweaks.
  wp; call (_ : true ==> true).
  + by proc; wp; while (true); auto.
  by wp; call forge_accepted_no_failure; auto; smt().
qed.

lemma reduced_game_good_probability &m :
  Pr[M_EUF_GCMA_WOTSC_NPRF(R_MEUFGCMAWOTSC_EUFNAGCMA_C(Observe(A)),
    O_MEUFGCMA_WOTSC_Default,FC.O_THFC_Default).main() @ &m :
    res /\ good_transcript Observe.public Observe.messages Observe.signatures] <=
  Pr[M_EUF_GCMA_WOTSC_NPRF(R_MEUFGCMAWOTSC_EUFNAGCMA_C(Observe(A)),
    O_MEUFGCMA_WOTSC_Default,FC.O_THFC_Default).main() @ &m :
    res /\ !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
proof.
  have hz : Pr[M_EUF_GCMA_WOTSC_NPRF(R_MEUFGCMAWOTSC_EUFNAGCMA_C(Observe(A)),
    O_MEUFGCMA_WOTSC_Default,FC.O_THFC_Default).main() @ &m :
    (res /\ good_transcript Observe.public Observe.messages Observe.signatures) /\
    gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs] = 0%r.
  + byphoare => //; hoare.
    conseq reduced_game_accepted_no_failure; smt().
  rewrite Pr[mu_split (gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs)] hz /=.
  by rewrite Pr[mu_sub]; smt().
qed.
end section.
