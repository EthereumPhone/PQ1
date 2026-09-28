(* #########################################################################
   NOT A CLOSURE MEMBER.  NOT A CONTROL.  A REPRODUCTION RECEIPT.

   This is an INDEPENDENT re-derivation of `badenc_is_one`
   (cdrafts-split/BadEncCountermodel.ec), written on 2026-08-31 against the
   CURRENT split tree BEFORE its author knew that file existed.  It uses a
   different adversary (module globals `BadEncArg.mz/mo/sg` rather than the free
   ops `cm`/`cm'`/`wad0`), and it compiled GREEN -- converging on the same helper
   shape (`pk_of_sig` ~ `pkfs_fun`), the same losslessness + hoare split, and the
   same statement.

   IT IS DELIBERATELY NOT PROMOTED.  One statement of this fact belongs in the
   cone, not two, and the older file is better documented and already carries
   four must-fail controls.  This copy is kept only as evidence that the result
   reproduces independently against base-c10-split as it now stands.

   Do not add it to closure-c10-split.txt or cert-controls-split.tsv.
   ######################################################################### *)
(* Development scratch for badenc_replay_pr1.  Moves into
   base-c10-split/WOTS_TW_ES.ec once proved. *)
require import AllCore List Distr IntDiv StdOrder StdBigop.
require import WOTS_TW_ES.
import EmsgWOTS.
import F.
import FC.

(* --- helper 1: equal codewords admit no chain collision --------------- *)
lemma has_chwcoll_refl_false (ps : pseed) (ad : adrs) (em : emsgWOTS) (sig sig' : sigWOTS) :
  ! has_chwcoll ps ad em em sig sig'.
proof.
rewrite /has_chwcoll hasPn => i _.
by rewrite /is_chwcoll /=; smt().
qed.

(* --- helper 2: nothing is disjoint-violating against an empty tweak list *)
lemma disj_wgpidxs_nil (adl : adrs list) : disj_wgpidxs adl [].
proof. by rewrite /disj_wgpidxs /= hasPn. qed.

(* --- helper 3: a single address is trivially wgpidx-unique ------------- *)
lemma uniq_wgpidxs1 (ad : adrs) : uniq_wgpidxs [ad].
proof. by rewrite /uniq_wgpidxs. qed.

(* --- the public key a signature reconstructs to, as a FUNCTION ---------- *)
op pk_of_sig (ps : pseed) (ad : adrs) (em : emsgWOTS) (sigl : dgstblock list)
  : dgstblock list =
  mkseq (fun (i : int) =>
           cf ps (set_chidx ad i) (BaseW.val em.[i]) (w - 1 - BaseW.val em.[i])
              (DigestBlock.val (nth witness sigl i))) len.

lemma pkfrom_fun _m _sig _ps _ad :
  hoare [WOTS_TW_ES.pkWOTS_from_sigWOTS :
             m = _m /\ sig = _sig /\ ps = _ps /\ ad = _ad
         ==> res = DBLL.insubd (pk_of_sig _ps _ad (encode_msgWOTS _m) (DBLL.val _sig))].
proof.
proc.
while (   ps = _ps /\ ad = _ad /\ sig = _sig /\ em = encode_msgWOTS _m
       /\ 0 <= size pkWOTS <= len
       /\ pkWOTS = mkseq (fun (i : int) =>
                      cf _ps (set_chidx _ad i)
                         (BaseW.val (encode_msgWOTS _m).[i])
                         (w - 1 - BaseW.val (encode_msgWOTS _m).[i])
                         (DigestBlock.val (nth witness (DBLL.val _sig) i))) (size pkWOTS)).
+ auto => /> &hr hge0 hle hinv hlt.
  rewrite size_rcons; split; 1: smt().
  by rewrite mkseqS 1:/# -hinv.
+ auto => />; split; 1: by rewrite mkseq0 /=; smt(ge2_len).
  move=> pk hge0 hle hnlt hinv.
  by rewrite /pk_of_sig hinv (: size pk = len) 1:/#.
qed.

(* --- the replay adversary ---------------------------------------------- *)
module BadEncArg = {
  var mz : msgWOTS   (* the message it QUERIES  *)
  var mo : msgWOTS   (* the message it FORGES on -- same codeword as mz *)
  var sg : sigWOTS   (* the signature the oracle handed back *)
}.

module A_Replay (O : Oracle_MEUFGCMA_WOTSTWESNPRF, OC : Oracle_THFC) = {
  proc choose() : unit = {
    var pk : pkWOTS;
    (pk, BadEncArg.sg) <@ O.query(witness, BadEncArg.mz);
  }

  proc forge(ps : pseed) : int * msgWOTS * sigWOTS = {
    return (0, BadEncArg.mo, BadEncArg.sg);
  }
}.

lemma badenc_replay_ll : islossless Game4_WOTSTWES_BadEnc(A_Replay).main.
proof.
islossless.
+ while (true) (len - size pkWOTS); auto; smt(size_rcons).
+ while (true) (len - size pk); auto; smt(size_rcons).
+ while (true) (len - size sig); auto; smt(size_rcons ddgstblock_ll).
qed.

lemma verify_fun _pk _ps _ad _m _sig :
  hoare [WOTS_TW_ES.verify :
             pk = (_pk, _ps, _ad) /\ m = _m /\ sig = _sig
         ==> res = (DBLL.insubd (pk_of_sig _ps _ad (encode_msgWOTS _m) (DBLL.val _sig)) = _pk)].
proof.
proc.
call (pkfrom_fun _m _sig _ps _ad).
by auto.
qed.

lemma badenc_replay_hoare :
  hoare [Game4_WOTSTWES_BadEnc(A_Replay).main :
             BadEncArg.mz <> BadEncArg.mo
          /\ encode_msgWOTS BadEncArg.mz = encode_msgWOTS BadEncArg.mo
          /\ P BadEncArg.mz
      ==> res /\ BadEncFlag.badenc].
proof.
proc.
inline Game4_WOTSTWES_BadEnc(A_Replay).A.choose Game4_WOTSTWES_BadEnc(A_Replay).A.forge
       O_Game34_WOTSTWES_AltX.query
       O_MEUFGCMA_WOTSTWESNPRF.init O_MEUFGCMA_WOTSTWESNPRF.get
       O_MEUFGCMA_WOTSTWESNPRF.nr_queries O_MEUFGCMA_WOTSTWESNPRF.dist_addresses
       O_MEUFGCMA_WOTSTWESNPRF.get_addresses
       O_THFC_Default.init O_THFC_Default.get_tweaks.
wp.
ecall (verify_fun pk ps ad m' sig').
wp.
while (   O_MEUFGCMA_WOTSTWESNPRF.ps = ps
       /\ m0 = BadEncArg.mz
       /\ ad0 = WAddress.val wad
       /\ em0 = encode_msgWOTS BadEncArg.mz
       /\ size sig0 = len
       /\ O_MEUFGCMA_WOTSTWESNPRF.qs = []
       /\ O_THFC_Default.tws = []
       /\ BadEncArg.mz <> BadEncArg.mo
       /\ encode_msgWOTS BadEncArg.mz = encode_msgWOTS BadEncArg.mo
       /\ P BadEncArg.mz
       /\ 0 <= size pk1 <= len
       /\ pk1 = mkseq (fun (j : int) =>
                    cf ps (set_chidx ad0 j) (BaseW.val em0.[j])
                       (w - 1 - BaseW.val em0.[j])
                       (DigestBlock.val (nth witness sig0 j))) (size pk1)).
+ auto => /> &hr hsz hne hcol hP hge0 hle hinv hlt.
  rewrite size_rcons; split; 1: smt().
  by rewrite mkseqS 1:/# -hinv.
wp.
while (   O_MEUFGCMA_WOTSTWESNPRF.ps = ps
       /\ m0 = BadEncArg.mz
       /\ ad0 = WAddress.val wad
       /\ em0 = encode_msgWOTS BadEncArg.mz
       /\ O_MEUFGCMA_WOTSTWESNPRF.qs = []
       /\ O_THFC_Default.tws = []
       /\ BadEncArg.mz <> BadEncArg.mo
       /\ encode_msgWOTS BadEncArg.mz = encode_msgWOTS BadEncArg.mo
       /\ P BadEncArg.mz
       /\ 0 <= size sig0 <= len).
+ auto => />; smt(size_rcons).
auto => />; smt(mkseq0 ge2_len ge1_c has_chwcoll_refl_false disj_wgpidxs_nil uniq_wgpidxs1 DBLL.insubdK).
qed.

(* ======================================================================= *)
(* THE RESULT.  Given ONE P-satisfying encoding collision, the charged      *)
(* BadEnc term is not merely unbounded -- it is EXACTLY 1.                  *)
(* ======================================================================= *)
lemma badenc_replay_pr1 &m :
     BadEncArg.mz{m} <> BadEncArg.mo{m}
  => encode_msgWOTS BadEncArg.mz{m} = encode_msgWOTS BadEncArg.mo{m}
  => P BadEncArg.mz{m}
  => Pr[Game4_WOTSTWES_BadEnc(A_Replay).main() @ &m : res /\ BadEncFlag.badenc] = 1%r.
proof.
move=> hne hcol hP.
byphoare (_ :    BadEncArg.mz <> BadEncArg.mo
              /\ encode_msgWOTS BadEncArg.mz = encode_msgWOTS BadEncArg.mo
              /\ P BadEncArg.mz ==> _) => //.
by conseq badenc_replay_ll badenc_replay_hoare.
qed.
